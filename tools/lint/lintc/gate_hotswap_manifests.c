/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-hotswap-eligible-scope, check-hotswap-static-state
 * Hot-swap manifest lint gates of the C23 lint runtime: gates that prove the
 * Tier-1 hot-swap eligibility manifest and the mutable-static-state ban hold
 * across every TU a hot-swap .so may be built from. Default landing spot for
 * a FUTURE gate port of the same shape (hot-swap manifest / eligibility
 * asserted by anchored patterns over a fixed file set); anything else
 * follows the landing policy in the older family headers.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"

/* check-hotswap-eligible-scope — port of tools/lint/check_hotswap_eligible_scope.sh
 * (now a shim). Every TU in the Tier-1 hot-swap eligibility manifest must be
 * an app-layer surface: consensus / validation / storage / net / coins /
 * reducer-stage code is never hot-swappable, not even in a dev build, because
 * a dlopen'd generation of any of those could silently diverge the node's
 * consensus state or the reducer fold. The gate parses
 * HOTSWAP_ELIGIBLE("<tu>") HOTSWAP_PROBE("<leaf>") rows, requires one probe
 * per row that resolves to exactly one resident case, rejects duplicate rows
 * and duplicate probe assignments, refuses forbidden-root / non-.c /
 * nonexistent paths, and requires each eligible TU to invoke an export macro.
 * Manifest and probe-case paths are overridable via ZCL_HOTSWAP_MANIFEST /
 * ZCL_HOTSWAP_PROBE_CASES so the lint-gate self-test can point at seeded
 * fixtures. */

#define HES_MAX 512
#define HES_PATH 320
#define HES_PROBE 160
#define HES_KEY 384

struct hes_pair { char path[HES_PATH]; char probe[HES_PROBE]; };

struct hes_re {
    regex_t path, pair, forbid, export;
};

static void hes_free(struct hes_re *r, int n)
{
    regex_t *re[] = { &r->path, &r->pair, &r->forbid, &r->export };
    for (int i = 0; i < n && i < 4; i++)
        regfree(re[i]);
}

static int hes_compile(struct hes_re *r)
{
    static const char *const pat[] = {
        "HOTSWAP_" "ELIGIBLE\\(\"([^\"]+)\"\\)",
        "^[[:space:]]*HOTSWAP_" "ELIGIBLE\\(\"([^\"]*)\"\\)[[:space:]]*"
            "HOTSWAP_" "PROBE\\(\"([^\"]*)\"\\)",
        "^(core|lib/consensus|lib/validation|lib/storage|lib/net|lib/coins"
            "|app/jobs)/",
        "(^|[^_])(ZCL_HOTSWAP_EXPORT_" "LEAVES|ZCL_HOTSWAP_LEAVES_" "END)"
            "[[:space:]]*\\(",
    };
    regex_t *re[] = { &r->path, &r->pair, &r->forbid, &r->export };
    for (int i = 0; i < 4; i++) {
        int err = regcomp(re[i], pat[i], REG_EXTENDED);
        if (err) {
            hes_free(r, i);
            return reg_fail(re[i], err);
        }
    }
    return 0;
}

/* grep -oE semantics: every non-overlapping match on the line yields one
 * path entry; the pair regex is line-anchored and yields at most one. */
static int hes_collect(FILE *f, const struct hes_re *r,
                       char paths[][HES_PATH], int *np,
                       struct hes_pair *pairs, int *nq)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        regmatch_t m[3];
        size_t off = 0;
        while (regexec(&r->path, line + off, 2, m, 0) == 0) {
            size_t len = (size_t)(m[1].rm_eo - m[1].rm_so);
            if (len >= HES_PATH || *np >= HES_MAX) {
                rc = die("z23-lint: hotswap-manifest overflow\n", "");
                break;
            }
            memcpy(paths[*np], line + off + m[1].rm_so, len);
            paths[*np][len] = '\0';
            (*np)++;
            off += (size_t)m[0].rm_eo;
        }
        if (rc)
            break;
        if (regexec(&r->pair, line, 3, m, 0) == 0) {
            size_t pl = (size_t)(m[1].rm_eo - m[1].rm_so);
            size_t ql = (size_t)(m[2].rm_eo - m[2].rm_so);
            if (pl >= HES_PATH || ql >= HES_PROBE || *nq >= HES_MAX) {
                rc = die("z23-lint: hotswap-manifest overflow\n", "");
                break;
            }
            memcpy(pairs[*nq].path, line + m[1].rm_so, pl);
            pairs[*nq].path[pl] = '\0';
            memcpy(pairs[*nq].probe, line + m[2].rm_so, ql);
            pairs[*nq].probe[ql] = '\0';
            (*nq)++;
        }
    }
    free(line);
    return rc;
}

/* A canonical probe is non-empty and drawn from [A-Za-z0-9_.] only. */
static int hes_probe_valid(const char *p)
{
    if (!p[0])
        return 0;
    for (; *p; p++)
        if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '.'))
            return 0;
    return 1;
}

/* grep -Fc '"<probe>",' — the number of LINES holding the fixed needle. */
static int hes_case_count(FILE *f, const char *probe)
{
    char needle[HES_PROBE + 3];
    int k = snprintf(needle, sizeof needle, "\"%s\",", probe);
    if (ovf(k, sizeof needle))
        return -2;
    char *line = NULL;
    size_t cap = 0;
    int cnt = 0;
    while (getline(&line, &cap, f) >= 0)
        if (strstr(line, needle))
            cnt++;
    int err = ferror(f);
    free(line);
    return err ? -2 : cnt;
}

static int hes_has_export(FILE *f, const struct hes_re *r)
{
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    while (!found && getline(&line, &cap, f) >= 0)
        found = regexec(&r->export, line, 0, NULL, 0) == 0;
    free(line);
    return found;
}

static int hes_note(FILE *viol, int *nv, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int k = vfprintf(viol, fmt, ap);
    va_end(ap);
    if (k < 0)
        return die("z23-lint: write failed\n", "");
    (*nv)++;
    return 0;
}

static int hes_find(char const (*set)[HES_PATH], int n, const char *key)
{
    for (int i = 0; i < n; i++)
        if (strcmp(set[i], key) == 0)
            return i;
    return -1;
}

int check_hotswap_eligible_scope_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    const char *manifest = getenv("ZCL_HOTSWAP_MANIFEST");
    if (!manifest || !manifest[0])
        manifest = "engine/composition/hotswap_eligible.def";
    const char *casesf = getenv("ZCL_HOTSWAP_PROBE_CASES");
    if (!casesf || !casesf[0])
        casesf = "engine/composition/hotswap_probe_cases.def";
    if (fputs("══ LINT: hot-swap eligibility manifest scope (app-layer only) ══\n",
              stdout) < 0)
        return die("z23-lint: write failed\n", "");
    if (access(manifest, R_OK) != 0) {
        fprintf(stderr, "check_hotswap_eligible_scope: FATAL — manifest '%s' "
                "missing/unreadable.\n", manifest);
        fputs("  Refusing to report 'clean' with no manifest to scan.\n", stderr);
        return 2;
    }
    if (access(casesf, R_OK) != 0) {
        fprintf(stderr, "check_hotswap_eligible_scope: FATAL — probe cases '%s' "
                "missing/unreadable.\n", casesf);
        return 2;
    }
    struct hes_re r;
    int rc = hes_compile(&r);
    if (rc)
        return rc;
    FILE *mf = fopen(manifest, "r");
    if (!mf) {
        hes_free(&r, 4);
        return die("z23-lint: cannot open %s\n", manifest);
    }
    static char paths[HES_MAX][HES_PATH];
    static struct hes_pair pairs[HES_MAX];
    int np = 0, nq = 0;
    rc = hes_collect(mf, &r, paths, &np, pairs, &nq);
    if (rc == 0 && ferror(mf))
        rc = die("z23-lint: read failed: %s\n", manifest);
    if (fclose(mf) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", manifest);
    if (rc == 0) {
        char hint[512];
        int k = snprintf(hint, sizeof hint,
                         "no HOTSWAP_" "ELIGIBLE(\"...\") entries parsed from %s",
                         manifest);
        if (ovf(k, sizeof hint))
            rc = 2;
        else
            rc = gate_require_scanned(np, 1, "check_hotswap_eligible_scope", hint);
    }
    if (rc) {
        hes_free(&r, 4);
        return rc;
    }
    if (nq != np) {
        fputs("FAIL: every HOTSWAP_" "ELIGIBLE row must carry exactly one "
              "HOTSWAP_" "PROBE on the same line\n", stderr);
        hes_free(&r, 4);
        return 1;
    }
    FILE *viol = tmpfile();
    if (!viol) {
        hes_free(&r, 4);
        return die("z23-lint: tmpfile failed\n", "");
    }
    int nv = 0;
    static char seen_paths[HES_MAX][HES_PATH];
    static char seen_keys[HES_MAX][HES_KEY];
    static char seen_owner[HES_MAX][HES_PATH];
    int nsp = 0, nsk = 0;
    for (int i = 0; rc == 0 && i < nq; i++) {
        const char *p = pairs[i].path;
        const char *probe = pairs[i].probe;
        if (!hes_probe_valid(probe))
            rc = hes_note(viol, &nv, "  %s (invalid canonical probe '%s')\n",
                          p, probe);
        int cc = -2;
        if (rc == 0) {
            FILE *cf = fopen(casesf, "r");
            if (!cf)
                rc = die("z23-lint: cannot open %s\n", casesf);
            else {
                cc = hes_case_count(cf, probe);
                if (fclose(cf) != 0 && cc >= 0)
                    cc = -2;
                if (cc < 0)
                    rc = die("z23-lint: read failed: %s\n", casesf);
            }
        }
        if (rc == 0 && cc != 1)
            rc = hes_note(viol, &nv,
                          "  %s (probe '%s' resolves to %d resident cases, "
                          "expected exactly one)\n", p, probe, cc);
        if (rc)
            break;
        char key[HES_KEY];
        int k = probe[0] ? snprintf(key, sizeof key, "%s", probe)
                         : snprintf(key, sizeof key, "__empty__:%s", p);
        if (ovf(k, sizeof key)) {
            rc = 2;
            break;
        }
        if (hes_find((char const (*)[HES_PATH])seen_paths, nsp, p) >= 0)
            rc = hes_note(viol, &nv, "  %s (duplicate eligibility row)\n", p);
        int di = -1;
        if (rc == 0) {
            for (int j = 0; j < nsk; j++)
                if (strcmp(seen_keys[j], key) == 0) {
                    di = j;
                    break;
                }
            if (di >= 0)
                rc = hes_note(viol, &nv,
                              "  %s (probe '%s' is already assigned to %s)\n",
                              p, probe, seen_owner[di]);
        }
        if (rc)
            break;
        if (nsp >= HES_MAX || (di < 0 && nsk >= HES_MAX)
            || strlen(p) >= HES_PATH) {
            rc = die("z23-lint: hotswap-manifest overflow\n", "");
            break;
        }
        strcpy(seen_paths[nsp++], p);
        if (di >= 0)
            /* The original bash assign overwrite makes the LAST writer the
             * reported owner, not the first. */
            strcpy(seen_owner[di], p);
        else {
            strcpy(seen_keys[nsk], key);
            strcpy(seen_owner[nsk], p);
            nsk++;
        }
    }
    for (int i = 0; rc == 0 && i < np; i++) {
        const char *p = paths[i];
        if (regexec(&r.forbid, p, 0, NULL, 0) == 0) {
            rc = hes_note(viol, &nv,
                          "  %s (under a forbidden consensus/state root)\n", p);
            continue;
        }
        size_t pl = strlen(p);
        if (!(pl > 2 && p[pl - 2] == '.' && p[pl - 1] == 'c')) {
            rc = hes_note(viol, &nv, "  %s (not a .c translation unit)\n", p);
            continue;
        }
        struct stat st;
        if (stat(p, &st) != 0 || !S_ISREG(st.st_mode)) {
            rc = hes_note(viol, &nv,
                          "  %s (manifest references a nonexistent file)\n", p);
            continue;
        }
        FILE *tf = fopen(p, "r");
        int found = 0;
        if (tf) {
            found = hes_has_export(tf, &r);
            if (fclose(tf) != 0)
                found = 0;
        }
        if (!found)
            rc = hes_note(viol, &nv,
                          "  %s (eligible TU exports no leaves: neither "
                          "ZCL_HOTSWAP_EXPORT_" "LEAVES nor ZCL_HOTSWAP_LEAVES_"
                          "END)\n", p);
    }
    hes_free(&r, 4);
    if (rc) {
        fclose(viol);
        return rc;
    }
    if (nv) {
        if (fseek(viol, 0, SEEK_SET) != 0) {
            fclose(viol);
            return die("z23-lint: fseek failed\n", "");
        }
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        while ((n = getline(&line, &cap, viol)) >= 0)
            if (fwrite(line, 1, (size_t)n, stdout) != (size_t)n) {
                free(line);
                fclose(viol);
                return die("z23-lint: write failed\n", "");
            }
        free(line);
        fclose(viol);
        fputs("FAIL: hot-swap eligibility manifest lists an out-of-scope TU.\n"
              "  Eligible TUs must be app-layer .c files that invoke\n"
              "  ZCL_HOTSWAP_EXPORT_" "LEAVES, NEVER under core, lib/consensus,\n"
              "  core/modules/validation, engine/modules/storage, "
              "core/modules/net, core/modules/coins, or app/jobs.\n", stdout);
        return 1;
    }
    fclose(viol);
    return printf("  OK: %d eligible TU(s), all app-layer surfaces\n", np) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

int check_hotswap_eligible_scope_selftest(void)
{
    struct hes_re r;
    int cr = hes_compile(&r);
    if (cr)
        return cr;
    int bad = 0;
    /* Collection: header-comment rows (no quotes) are ignored, an
     * eligible-only row is a path but not a pair, leading whitespace and
     * trailing text on a pair row are accepted. */
    static const char mfst[] =
        "/* HOTSWAP_" "ELIGIBLE(path) HOTSWAP_" "PROBE(tool) header row */\n"
        "HOTSWAP_" "ELIGIBLE(\"engine/controllers/src/a.c\") HOTSWAP_" "PROBE(\"core.status\")\n"
        "  HOTSWAP_" "ELIGIBLE(\"engine/controllers/src/b.c\")   HOTSWAP_" "PROBE(\"ops.metrics\")  /* x */\n"
        "HOTSWAP_" "ELIGIBLE(\"engine/controllers/src/c.c\")\n";
    static char paths[HES_MAX][HES_PATH];
    static struct hes_pair pairs[HES_MAX];
    int np = 0, nq = 0;
    FILE *mf = fmemopen((void *)mfst, sizeof mfst - 1, "r");
    if (!mf)
        bad = 1;
    else {
        bad |= hes_collect(mf, &r, paths, &np, pairs, &nq) != 0;
        fclose(mf);
    }
    if (np != 3 || nq != 2 || strcmp(paths[0], "engine/controllers/src/a.c")
        || strcmp(pairs[1].probe, "ops.metrics")) {
        fputs("check_hotswap_eligible_scope selftest: collect mismatch\n", stderr);
        bad = 1;
    }
    /* Probe validity. */
    bad |= !hes_probe_valid("core.status") || !hes_probe_valid("UP_9.x");
    bad |= hes_probe_valid("") || hes_probe_valid("bad probe")
        || hes_probe_valid("a/b");
    /* Resident-case counting counts LINES holding the fixed needle. */
    static const char cases[] =
        "HOTSWAP_PROBE_CASE(\"core.status\", x)\n"
        "two \"core.status\", needles one line\n"
        "HOTSWAP_PROBE_CASE(\"ops.metrics\", y)\n";
    FILE *cf = fmemopen((void *)cases, sizeof cases - 1, "r");
    if (!cf)
        bad = 1;
    else {
        int c1 = hes_case_count(cf, "core.status");
        bad |= c1 != 2;
        rewind(cf);
        bad |= hes_case_count(cf, "ops.metrics") != 1;
        rewind(cf);
        bad |= hes_case_count(cf, "no.such") != 0;
        fclose(cf);
    }
    /* Forbidden roots keep the original's exact anchoring. */
    bad |= regexec(&r.forbid, "core/consensus/src/x.c", 0, NULL, 0) != 0;
    bad |= regexec(&r.forbid, "lib/consensus/src/pow.c", 0, NULL, 0) != 0;
    bad |= regexec(&r.forbid, "app/jobs/src/j.c", 0, NULL, 0) != 0;
    bad |= regexec(&r.forbid, "engine/controllers/src/a.c", 0, NULL, 0) == 0;
    bad |= regexec(&r.forbid, "xcore/x.c", 0, NULL, 0) == 0;
    /* Export-macro detection accepts either spelling, rejects a comment
     * mention without the call paren. */
    static const char with_exp[] =
        "ZCL_HOTSWAP_EXPORT_" "LEAVES(status_leaves)\n";
    static const char with_end[] =
        "  ZCL_HOTSWAP_LEAVES_" "END (x)\n";
    static const char without[] =
        "/* ZCL_HOTSWAP_EXPORT_" "LEAVES without paren */\n";
    FILE *ef = fmemopen((void *)with_exp, sizeof with_exp - 1, "r");
    bad |= !ef || !hes_has_export(ef, &r);
    if (ef) fclose(ef);
    ef = fmemopen((void *)with_end, sizeof with_end - 1, "r");
    bad |= !ef || !hes_has_export(ef, &r);
    if (ef) fclose(ef);
    ef = fmemopen((void *)without, sizeof without - 1, "r");
    bad |= !ef || hes_has_export(ef, &r);
    if (ef) fclose(ef);
    hes_free(&r, 4);
    return st_ok(bad, "check_hotswap_eligible_scope selftest: OK\n");
}


/* check-hotswap-static-state — port of
 * tools/lint/check_hotswap_static_state.sh (now a shim). Every TU that can be
 * recompiled into a hot-swap .so must define NO mutable file-scope statics: a
 * generation/module .so recompiles the whole TU, so a mutable file-scope
 * static becomes a fresh zero-initialized copy inside the .so and the live
 * process state is silently lost. The scan set is the encounter-ordered union
 * of the eligible, swappable, and island manifests, each parsed with the
 * build-free column-1 paren-depth walk (a macro named in a header comment
 * does not parse; a multi-line invocation does). The per-TU heuristic flags a
 * file-scope line starting "static" that is not const, carries no '(', and
 * has an initializer ('='), array bracket ('['), or aggregate opener
 * ('{' + blanks at end of line); a same-line hotswap-static-ok comment
 * escapes it. Manifest paths are overridable via ZCL_HOTSWAP_MANIFEST /
 * ZCL_HOTSWAP_SWAPPABLE_MANIFEST / ZCL_HOTSWAP_ISLAND_MANIFEST so the
 * lint-gate self-test can point at seeded fixtures.
 * Parity notes: the awk original rebuilds the file as records plus '\n', so a
 * final line without a newline still gets one in the scan buffer; violations
 * accumulate across ALL files and print only in the FAIL branch (a later
 * missing TU exits 2 without flushing earlier hits); the union keeps
 * encounter order (no sort); empty string-literal args count toward the
 * gate_require_scanned floors but are dropped from the union. */

#define HSS_MAX_PATHS 512
#define HSS_PATH 4096
#define HSS_SPEC 8192
#define HSS_MANIFEST_CAP (1u << 20)
#define HSS_VIOL_CAP (1u << 20)

static const char k_hss_eligible_tok[] = "HOTSWAP_" "ELIGIBLE(";
static const char k_hss_swappable_tok[] = "HOTSWAP_" "SWAPPABLE(";
static const char k_hss_island_tok[] = "HOTSWAP_" "ISLAND(";

/* awk '{ buf = buf $0 "\n" }': the whole file, with a newline appended after
 * every record — including a final line that lacks one. */
static int hss_slurp(const char *path, char *buf, size_t cap, size_t *out_n)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    size_t n = fread(buf, 1, cap - 1, f);
    int rc = 0;
    if (ferror(f))
        rc = die("z23-lint: cannot read %s\n", path);
    else if (!feof(f))
        rc = die("z23-lint: manifest too large: %s\n", path);
    fclose(f);
    if (rc)
        return rc;
    if (n > 0 && buf[n - 1] != '\n')
        buf[n++] = '\n';
    buf[n] = '\0';
    *out_n = n;
    return 0;
}

/* Column-1 paren-depth walk: every invocation of tok (which includes its
 * open paren) starting at column 1 contributes its first (second=0) or second
 * (second=1) string literal's raw content. Parens inside strings do not
 * count; backslash escapes only shield the depth counter, the literal
 * extraction itself is the naive "..." pair, exactly like the awk original. */
static int hss_collect(const char *buf, size_t n, const char *tok, int second,
                       char out[][HSS_PATH], int *nout)
{
    size_t L = strlen(tok);
    size_t i = 0;
    while (i < n) {
        if (i + L > n || memcmp(buf + i, tok, L) != 0
            || (i > 0 && buf[i - 1] != '\n')) {
            i++;
            continue;
        }
        size_t j = i + L;
        int depth = 1, in_str = 0, esc = 0;
        char spec[HSS_SPEC];
        size_t sl = 0;
        while (j < n && depth > 0) {
            char c = buf[j];
            if (in_str) {
                if (esc)
                    esc = 0;
                else if (c == '\\')
                    esc = 1;
                else if (c == '"')
                    in_str = 0;
            } else {
                if (c == '"')
                    in_str = 1;
                else if (c == '(')
                    depth++;
                else if (c == ')')
                    depth--;
            }
            if (depth > 0) {
                if (sl + 1 >= sizeof spec)
                    return die("z23-lint: hotswap manifest arg overflow\n", "");
                spec[sl++] = c;
            }
            j++;
        }
        spec[sl] = '\0';
        const char *p = spec;
        for (int k = 0; k < (second ? 2 : 1); k++) {
            const char *a = strchr(p, '"');
            if (!a)
                break;
            const char *b = strchr(a + 1, '"');
            if (!b)
                break;
            if (k == (second ? 1 : 0)) {
                size_t len = (size_t)(b - a - 1);
                if (len >= HSS_PATH || *nout >= HSS_MAX_PATHS)
                    return die("z23-lint: hotswap manifest path overflow\n", "");
                memcpy(out[*nout], a + 1, len);
                out[*nout][len] = '\0';
                (*nout)++;
            }
            p = b + 1;
        }
        i = j;
    }
    return 0;
}

/* awk /\<const\>/: the letters c-o-n-s-t with a non-[A-Za-z0-9_] (or string
 * edge) on both sides. */
static int hss_has_word_const(const char *s)
{
    const char *p = s;
    while ((p = strstr(p, "const")) != NULL) {
        int left = p == s
            || !(isalnum((unsigned char)p[-1]) || p[-1] == '_');
        int right = !(isalnum((unsigned char)p[5]) || p[5] == '_');
        if (left && right)
            return 1;
        p += 5;
    }
    return 0;
}

/* One newline-stripped line through the mutable-static heuristic. */
static int hss_flag_line(const char *line)
{
    if (strstr(line, "hotswap-static-" "ok:") != NULL)
        return 0; /* explicit allowlist escape */
    if (strncmp(line, "static", 6) != 0 || (line[6] != ' ' && line[6] != '\t'))
        return 0;
    if (hss_has_word_const(line))
        return 0; /* immutable */
    if (strchr(line, '(') != NULL)
        return 0; /* function declarator/prototype */
    if (strchr(line, '=') != NULL || strchr(line, '[') != NULL)
        return 1;
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == ' ' || line[n - 1] == '\t'))
        n--;
    return n > 0 && line[n - 1] == '{'; /* opens an aggregate */
}

static int hss_scan_file(const char *path, char *viol, size_t cap, size_t *used)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0; /* awk-in-$(...) loses the race the same way: no hits */
    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &lcap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if (!hss_flag_line(line))
            continue;
        int k = snprintf(viol + *used, cap - *used, "%s:%d: %s\n",
                         path, lineno, line);
        if (ovf(k, cap - *used)) {
            rc = 2;
            break;
        }
        *used += (size_t)k;
    }
    free(line);
    fclose(f);
    return rc;
}

int check_hotswap_static_state_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    const char *manifest = getenv("ZCL_HOTSWAP_MANIFEST");
    if (!manifest)
        manifest = "engine/composition/hotswap_eligible.def";
    const char *swappable = getenv("ZCL_HOTSWAP_SWAPPABLE_MANIFEST");
    if (!swappable)
        swappable = "engine/composition/hotswap_swappable.def";
    const char *islands = getenv("ZCL_HOTSWAP_ISLAND_MANIFEST");
    if (!islands)
        islands = "engine/composition/hotswap_islands.def";

    fputs("══ LINT: hot-swap recompiled TUs hold no mutable file-scope statics ══\n",
          stdout);

    const char *const m[3] = { manifest, swappable, islands };
    for (int i = 0; i < 3; i++) {
        if (access(m[i], R_OK) != 0) {
            fprintf(stderr, "check_hotswap_static_state: FATAL — manifest '%s' missing/unreadable.\n",
                    m[i]);
            fputs("  Refusing to report 'clean' with a manifest missing from the scan set.\n",
                  stderr);
            return 2;
        }
    }

    static char buf[HSS_MANIFEST_CAP];
    static char eligible[HSS_MAX_PATHS][HSS_PATH];
    static char swap[HSS_MAX_PATHS][HSS_PATH];
    static char isl_lists[HSS_MAX_PATHS][HSS_PATH];
    static char isl[HSS_MAX_PATHS][HSS_PATH];
    int ne = 0, ns = 0, nl = 0, ni = 0;
    size_t n = 0;
    if (hss_slurp(manifest, buf, sizeof buf, &n)
        || hss_collect(buf, n, k_hss_eligible_tok, 0, eligible, &ne))
        return 2;
    if (hss_slurp(swappable, buf, sizeof buf, &n)
        || hss_collect(buf, n, k_hss_swappable_tok, 0, swap, &ns))
        return 2;
    if (hss_slurp(islands, buf, sizeof buf, &n)
        || hss_collect(buf, n, k_hss_island_tok, 1, isl_lists, &nl))
        return 2;
    for (int i = 0; i < nl; i++) {
        char list[HSS_PATH];
        memcpy(list, isl_lists[i], strlen(isl_lists[i]) + 1);
        for (char *save = NULL, *p = strtok_r(list, " \t\n", &save);
             p; p = strtok_r(NULL, " \t\n", &save)) {
            if (ni >= HSS_MAX_PATHS)
                return die("z23-lint: hotswap manifest path overflow\n", "");
            size_t len = strlen(p);
            memcpy(isl[ni], p, len + 1);
            ni++;
        }
    }

    char hint[4096];
    if (ovf(snprintf(hint, sizeof hint,
                     "no HOTSWAP_" "ELIGIBLE(\"...\") entries parsed from %s",
                     manifest), sizeof hint))
        return 2;
    int rc = gate_require_scanned(ne, 1, "check_hotswap_static_state", hint);
    if (rc)
        return rc;
    if (ovf(snprintf(hint, sizeof hint,
                     "no HOTSWAP_" "SWAPPABLE(\"...\") entries parsed from %s",
                     swappable), sizeof hint))
        return 2;
    rc = gate_require_scanned(ns, 1, "check_hotswap_static_state", hint);
    if (rc)
        return rc;
    if (ovf(snprintf(hint, sizeof hint,
                     "no HOTSWAP_" "ISLAND implementation members parsed from %s",
                     islands), sizeof hint))
        return 2;
    rc = gate_require_scanned(ni, 1, "check_hotswap_static_state", hint);
    if (rc)
        return rc;

    /* Union, de-duplicated, encounter order; empty args drop out. */
    static char paths[HSS_MAX_PATHS][HSS_PATH];
    int np = 0;
    for (int src = 0; src < 3; src++) {
        char (*set)[HSS_PATH] = src == 0 ? eligible : src == 1 ? swap : isl;
        int cnt = src == 0 ? ne : src == 1 ? ns : ni;
        for (int i = 0; i < cnt; i++) {
            if (!set[i][0])
                continue;
            int dup = 0;
            for (int j = 0; j < np; j++)
                if (strcmp(paths[j], set[i]) == 0) {
                    dup = 1;
                    break;
                }
            if (dup)
                continue;
            if (np >= HSS_MAX_PATHS)
                return die("z23-lint: hotswap manifest path overflow\n", "");
            strcpy(paths[np++], set[i]);
        }
    }
    if (ovf(snprintf(hint, sizeof hint,
                     "the union of %s and %s parsed to zero TUs",
                     manifest, swappable), sizeof hint))
        return 2;
    rc = gate_require_scanned(np, 1, "check_hotswap_static_state", hint);
    if (rc)
        return rc;

    static char viol[HSS_VIOL_CAP];
    size_t vused = 0;
    viol[0] = '\0';
    int scanned = 0;
    for (int i = 0; i < np; i++) {
        struct stat st;
        if (stat(paths[i], &st) != 0 || !S_ISREG(st.st_mode)) {
            fprintf(stderr, "check_hotswap_static_state: FATAL — hot-swap TU '%s' does not exist.\n",
                    paths[i]);
            fputs("  A manifest drifted; refusing to pass off an unscannable file.\n",
                  stderr);
            return 2;
        }
        scanned++;
        /* hits="$(...)" strips the trailing newline, then the shell appends
         * one: the violations block is exactly the hit lines, no separator. */
        if (hss_scan_file(paths[i], viol, sizeof viol, &vused))
            return 2;
    }
    rc = gate_require_scanned(scanned, 1, "check_hotswap_static_state",
                              "no hot-swap TU scanned");
    if (rc)
        return rc;

    if (vused > 0) {
        if (fwrite(viol, 1, vused, stdout) != vused)
            return die("z23-lint: write failed\n", "");
        fputs("FAIL: a hot-swap recompiled TU defines a mutable file-scope static.\n"
              "  Move it to a sibling NON-eligible resident trampoline TU (a .so\n"
              "  gets its own zero copy), or, if provably swap-safe, annotate the\n"
              "  declaration line with a comment reading  hotswap-static-"
              "ok: <reason>.\n",
              stdout);
        return 1;
    }
    printf("  OK: %d hot-swap TU(s) free of mutable file-scope statics\n",
           scanned);
    printf("      (%d eligible + %d swappable + %d island members, de-duplicated)\n",
           ne, ns, ni);
    return 0;
}

static int hss_want(const char *tag, int got, int w, const char *s)
{
    if (got != w) {
        fprintf(stderr, "%s selftest: want %d: %s\n", tag, w, s);
        return 1;
    }
    return 0;
}

int check_hotswap_static_state_selftest(void)
{
    const char *t = "check_hotswap_static_state";
    char out[8][HSS_PATH];
    int nout = 0, bad = 0;

    /* column-1 anchoring: a comment mention does not parse, a real row does */
    const char *m1 = " * HOTSWAP_" "ELIGIBLE(\"fake/comment.c\") in a comment\n"
                     "HOTSWAP_" "ELIGIBLE(\"engine/real.c\") HOTSWAP_"
                     "PROBE(\"leaf\")\n";
    bad |= hss_collect(m1, strlen(m1), k_hss_eligible_tok, 0, out, &nout)
        | hss_want(t, nout == 1 && strcmp(out[0], "engine/real.c") == 0, 1,
                   "column-1 anchoring");

    /* multi-line invocation parses; parens inside strings do not count */
    nout = 0;
    const char *m2 = "HOTSWAP_" "ELIGIBLE(\n    \"engine/multi.c\"\n)\n"
                     "HOTSWAP_" "ELIGIBLE(\"engine/pa)ren.c\")\n";
    bad |= hss_collect(m2, strlen(m2), k_hss_eligible_tok, 0, out, &nout)
        | hss_want(t, nout == 2 && strcmp(out[0], "engine/multi.c") == 0
                       && strcmp(out[1], "engine/pa)ren.c") == 0, 1,
                   "multi-line and in-string paren");

    /* naive literal extraction: an escaped quote still terminates it */
    nout = 0;
    const char *m3 = "HOTSWAP_" "ELIGIBLE(\"engine/es\\\" \"c.c\")\n";
    bad |= hss_collect(m3, strlen(m3), k_hss_eligible_tok, 0, out, &nout)
        | hss_want(t, nout == 1 && strcmp(out[0], "engine/es\\") == 0, 1,
                   "escaped quote ends the literal (awk-naive)");

    /* second-arg extraction for islands */
    nout = 0;
    const char *m4 = "HOTSWAP_" "ISLAND(\"engine/owner.c\",\n"
                     "               \"m1.c m2.c\")\n";
    bad |= hss_collect(m4, strlen(m4), k_hss_island_tok, 1, out, &nout)
        | hss_want(t, nout == 1 && strcmp(out[0], "m1.c m2.c") == 0, 1,
                   "island member list is the second literal");

    /* an invocation with no string literal emits nothing; an empty literal
     * emits an empty string (floor-counted, union-dropped) */
    nout = 0;
    const char *m5 = "HOTSWAP_" "ELIGIBLE()\nHOTSWAP_" "ELIGIBLE(\"\")\n";
    bad |= hss_collect(m5, strlen(m5), k_hss_eligible_tok, 0, out, &nout)
        | hss_want(t, nout == 1 && out[0][0] == '\0', 1,
                   "no-literal skipped, empty literal counted");

    /* detector heuristic */
    bad |= hss_want(t, hss_flag_line("static int g_counter = 0;"), 1,
                   "initialized mutable static flags")
        | hss_want(t, hss_flag_line("static int g_buf[4];"), 1,
                   "array static flags")
        | hss_want(t, hss_flag_line("static struct s g_x = {"), 1,
                   "aggregate opener flags")
        | hss_want(t, hss_flag_line("static const int k_t[] = {1};"), 0,
                   "const is immutable")
        | hss_want(t, hss_flag_line("static int f(void);"), 0,
                   "declarator with paren is skipped")
        | hss_want(t, hss_flag_line("static int g_x = 0; /* hotswap-static-"
                                    "ok: resident */"), 0,
                   "escape comment skips")
        | hss_want(t, hss_flag_line("	static int g_x = 1;"), 0,
                   "indented static is not file scope")
        | hss_want(t, hss_flag_line("staticint g_x = 1;"), 0,
                   "no blank after static")
        | hss_want(t, hss_flag_line("static constint g_x = 1;"), 1,
                   "constint is not the const word")
        | hss_want(t, hss_flag_line("static struct s g_x;"), 0,
                   "plain declaration without initializer passes");

    return st_ok(bad, "check_hotswap_static_state selftest: OK\n");
}

