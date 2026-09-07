/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: C23 lint gate — port of
 * tools/lint/check_supervisor_progress_declared.sh
 * (check-supervisor-progress-declared). Every file that registers a
 * supervised child (liveness_contract_init(...)) must, per child, either
 * ARM progress detection (supervisor_set_progress_max_quiet(id, <non-zero>)
 * or a raw non-zero store to <contract>.progress_max_quiet_us) or declare
 * itself EXEMPT (supervisor_set_progress_exempt(id, "why")). A file's debt
 * is max(0, children - policies); a per-file baseline caps how much debt is
 * tolerated, shrink-only: a file whose measured debt exceeds its baselined
 * allowance is a violation, and a baselined file whose debt reached zero is
 * a STALE row that must be deleted. See the replaced script's header for
 * the full "why" (a 13k-tick, zero-result service nothing could see).
 *
 * This ratchet's per-file "measured <= baselined ceiling" tolerance (a debt
 * that shrank below its baseline number is fine; only growth beyond it and
 * a debt that reached zero are graded) is NOT the tree's generic exact-pin
 * shrink-only ratchet (lint_base_* in lib.c — that requires re-pinning on
 * every improvement, which is a different contract this script never had).
 * Baseline load matches gate_load_kv_file (gate_lib.sh): `#` truncates a
 * comment anywhere on the line, blank lines skip, first/last whitespace-
 * separated token are key/value — not lint_base_load's `key:M` format.
 * Single-gate family file.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { SPD_MAX = 512, SPD_ROW = RS_PATH + 24, SPD_ROOT_CAP = 16,
       SPD_ROOT_BUF = 1024, SPD_LINE = CSTRIP_LINE_MAX };

static const char k_spd_roots_text[] = "core engine contexts cognition platform";
static const char k_spd_base_rel[] = "tools/lint/supervisor_progress_baseline.txt";
static const char k_spd_excl_dir[] = "tests/harness/include/test/";
static const char k_spd_excl_file[] = "platform/modules/util/src/supervisor.c";

struct spd_kv { char key[SPD_ROW]; long val; };
struct spd_baseline { struct spd_kv row[SPD_MAX]; int n; };

struct spd_count { char path[RS_PATH]; int kids, pol; };
struct spd_counts { struct spd_count row[SPD_MAX]; int n; };

struct spd_roots { char buf[SPD_ROOT_BUF]; const char *v[SPD_ROOT_CAP]; int n; };

/* ── baseline: gate_load_kv_file semantics (gate_lib.sh), NOT lint_base_* ── */

static void spd_trim(char *s)
{
    char *p = s;
    while (*p == ' ' || *p == '\t')
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = '\0';
}

static int spd_base_find(const struct spd_baseline *b, const char *key)
{
    for (int i = 0; i < b->n; i++)
        if (strcmp(b->row[i].key, key) == 0)
            return i;
    return -1;
}

static int spd_base_load(struct spd_baseline *b, const char *path)
{
    b->n = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return errno == ENOENT ? 0 : die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        char buf[SPD_LINE];
        if ((size_t)n >= sizeof buf) {
            rc = die("z23-lint: line too long: %s\n", path);
            break;
        }
        memcpy(buf, line, (size_t)n);
        buf[n] = '\0';
        char *h = strchr(buf, '#');
        if (h)
            *h = '\0';
        char *nl = strpbrk(buf, "\r\n");
        if (nl)
            *nl = '\0';
        spd_trim(buf);
        if (buf[0] == '\0')
            continue;
        char *sp = strrchr(buf, ' ');
        if (!sp)
            sp = strrchr(buf, '\t');
        if (!sp) {
            rc = die("z23-lint: malformed baseline row (no value): %s\n",
                     path);
            break;
        }
        *sp = '\0';
        char *valtxt = sp + 1;
        spd_trim(buf);
        char *end = NULL;
        long v = strtol(valtxt, &end, 10);
        if (!end || *end != '\0') {
            rc = die("z23-lint: malformed baseline value: %s\n", path);
            break;
        }
        if (b->n >= SPD_MAX || strlen(buf) >= SPD_ROW) {
            rc = die("z23-lint: derived buffer overflow\n", "");
            break;
        }
        memcpy(b->row[b->n].key, buf, strlen(buf) + 1);
        b->row[b->n].val = v;
        b->n++;
    }
    return fin(f, line, path, rc);
}

/* ── scan roots (space-separated override) ─────────────────────────────── */

static int spd_parse_roots(const char *text, struct spd_roots *r)
{
    r->n = 0;
    if (ovf(snprintf(r->buf, sizeof r->buf, "%s", text), sizeof r->buf))
        return 2;
    char *p = r->buf;
    while (*p != '\0') {
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0')
            break;
        if (r->n >= SPD_ROOT_CAP)
            return die("z23-lint: derived buffer overflow\n", "");
        r->v[r->n++] = p;
        while (*p != '\0' && *p != ' ' && *p != '\t')
            p++;
        if (*p != '\0')
            *p++ = '\0';
    }
    return 0;
}

/* ── file collection: find <root> -type f -name '*.c', minus the two
 * fixed exclusions the script names (see the header: lib/test fixtures and
 * the supervisor primitive itself, which DEFINES the functions rather than
 * calling them). Plain filesystem walk in every mode — the original script
 * never touches git. */

struct spd_collect {
    const struct spd_roots *roots;
    struct spd_counts *cur;
    int files_scanned;
};

static int spd_excluded(const char *path)
{
    if (strcmp(path, k_spd_excl_file) == 0)
        return 1;
    size_t n = strlen(k_spd_excl_dir);
    return strncmp(path, k_spd_excl_dir, n) == 0;
}

static int spd_counts_get(struct spd_counts *c, const char *path)
{
    for (int i = 0; i < c->n; i++)
        if (strcmp(c->row[i].path, path) == 0)
            return i;
    if (c->n >= SPD_MAX || strlen(path) >= RS_PATH)
        return -2;
    memcpy(c->row[c->n].path, path, strlen(path) + 1);
    c->row[c->n].kids = 0;
    c->row[c->n].pol = 0;
    return c->n++;
}

/* Strip a trailing block-comment open and a line comment, matching the awk
 * original's two-sub sequence (cut from the first "//" and separately from
 * the first block-comment opener) — a leading substring cut, not a real
 * comment-state tracker (the script never handles a comment that spans
 * lines either). */
static void spd_strip_trailing_comment(char *line)
{
    char *c = strstr(line, "//");
    char *b = strstr(line, "/*");
    if (b && (!c || b < c))
        c = b;
    if (c)
        *c = '\0';
}

static int spd_ident_char(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')
        || (c >= 'a' && c <= 'z') || c == '_';
}

/* Literal-name match requiring a `(` (optional space/tab first) right
 * after the name — the awk original's `name[ \t]*\(` shape — and no
 * identifier char right before it, so a longer identifier that merely
 * contains `name` as a substring never counts. */
static const char *spd_find_call(const char *line, const char *name)
{
    size_t nlen = strlen(name);
    const char *p = line;
    while ((p = strstr(p, name)) != NULL) {
        if (p > line && spd_ident_char((unsigned char)p[-1])) {
            p++;
            continue;
        }
        const char *q = p + nlen;
        while (*q == ' ' || *q == '\t')
            q++;
        if (*q != '(') {
            p++;
            continue;
        }
        return p;
    }
    return NULL;
}

/* value_of(): strip whitespace, a trailing ';', a trailing ')' run, and any
 * cast token, anywhere — the awk original strips from the RIGHT first so a
 * cast like "(int64_t)0)" is not cut in half. */
static void spd_value_of(const char *in, char *out, size_t cap)
{
    char tmp[SPD_LINE];
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0' && j + 1 < sizeof tmp; i++)
        if (in[i] != ' ' && in[i] != '\t')
            tmp[j++] = in[i];
    tmp[j] = '\0';
    while (j > 0 && tmp[j - 1] == ';')
        tmp[--j] = '\0';
    while (j > 0 && tmp[j - 1] == ')')
        tmp[--j] = '\0';
    static const char *const casts[] = {
        "(int64_t)", "(int)", "(long)", "(longlong)", "(uint64_t)"
    };
    for (;;) {
        int removed = 0;
        for (size_t k = 0; k < sizeof casts / sizeof casts[0]; k++) {
            const char *hit = strstr(tmp, casts[k]);
            if (hit) {
                size_t clen = strlen(casts[k]);
                memmove((char *)hit, hit + clen, strlen(hit + clen) + 1);
                removed = 1;
            }
        }
        if (!removed)
            break;
    }
    snprintf(out, cap, "%s", tmp);
}

static int spd_is_zero(const char *s)
{
    char v[SPD_LINE];
    spd_value_of(s, v, sizeof v);
    return strcmp(v, "0") == 0 || strcmp(v, "0L") == 0
        || strcmp(v, "0LL") == 0 || strcmp(v, "0U") == 0 || v[0] == '\0';
}

static int spd_blank(const char *s)
{
    for (; *s; s++)
        if (*s != ' ' && *s != '\t')
            return 0;
    return 1;
}

struct spd_file_state { int kids, pol, pending; };

static void spd_count_line(const char *raw, struct spd_file_state *st)
{
    char line[SPD_LINE];
    snprintf(line, sizeof line, "%s", raw);
    spd_strip_trailing_comment(line);

    if (spd_find_call(line, "liveness_contract_init") != NULL)
        st->kids++;
    if (spd_find_call(line, "supervisor_set_progress_exempt") != NULL)
        st->pol++;

    const char *mq = spd_find_call(line, "supervisor_set_progress_max_quiet");
    if (mq) {
        const char *comma = strchr(mq, ',');
        if (comma && !spd_is_zero(comma + 1))
            st->pol++;
    }

    const char *pmqu = strstr(line, "progress_max_quiet_us");
    if (pmqu) {
        const char *q = pmqu + strlen("progress_max_quiet_us");
        while (*q == ' ' || *q == '\t')
            q++;
        if (*q == ',') {
            const char *comma = q;
            if (spd_blank(comma + 1)) {
                st->pending = 1;
            } else {
                if (!spd_is_zero(comma + 1))
                    st->pol++;
                st->pending = 0;
            }
            return;
        }
    }
    if (st->pending) {
        st->pending = 0;
        if (!spd_is_zero(line))
            st->pol++;
    }
}

static int spd_scan_file(const char *path, void *ctx)
{
    struct spd_collect *c = ctx;
    if (spd_excluded(path))
        return 0;
    c->files_scanned++;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    struct spd_file_state st = {0, 0, 0};
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if ((size_t)n >= SPD_LINE) {
            int rc = die("z23-lint: line too long: %s\n", path);
            free(line);
            fclose(f);
            return rc;
        }
        spd_count_line(line, &st);
    }
    int rc = fin(f, line, path, 0);
    if (rc)
        return rc;
    if (st.kids <= 0)
        return 0;
    int idx = spd_counts_get(c->cur, path);
    if (idx == -2)
        return die("z23-lint: derived buffer overflow\n", "");
    c->cur->row[idx].kids = st.kids;
    c->cur->row[idx].pol = st.pol;
    return 0;
}

static int spd_collect(struct spd_collect *c, int *files_scanned)
{
    c->files_scanned = 0;
    int rc = 0;
    for (int i = 0; rc == 0 && i < c->roots->n; i++)
        rc = walk_src(c->roots->v[i], 0, spd_scan_file, c);
    *files_scanned = c->files_scanned;
    return rc;
}

/* ── verdict ─────────────────────────────────────────────────────────────
 */

struct spd_report {
    char viol[SPD_MAX][SPD_ROW + 64];
    int nviol;
    char stale[SPD_MAX][SPD_ROW];
    int nstale;
    int declared_files, total_children, total_debt, tolerated;
};

static int spd_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int spd_classify(struct spd_report *r, const struct spd_counts *cur,
                        struct spd_baseline *base)
{
    unsigned char hit[SPD_MAX] = {0};
    for (int i = 0; i < cur->n; i++) {
        const struct spd_count *row = &cur->row[i];
        r->total_children += row->kids;
        int debt = row->kids - row->pol;
        if (debt < 0)
            debt = 0;
        if (debt == 0) {
            r->declared_files++;
            continue;
        }
        r->total_debt += debt;
        int bi = spd_base_find(base, row->path);
        if (bi >= 0) {
            hit[bi] = 1;
            if (debt <= base->row[bi].val) {
                r->tolerated++;
                continue;
            }
            if (r->nviol >= SPD_MAX)
                return die("z23-lint: too many violations to report\n", "");
            snprintf(r->viol[r->nviol++], sizeof r->viol[0],
                    "%s — %d undeclared child(ren), baseline allows %ld",
                    row->path, debt, base->row[bi].val);
        } else {
            if (r->nviol >= SPD_MAX)
                return die("z23-lint: too many violations to report\n", "");
            snprintf(r->viol[r->nviol++], sizeof r->viol[0],
                    "%s — %d undeclared child(ren), not in the baseline",
                    row->path, debt);
        }
    }
    for (int i = 0; i < base->n; i++) {
        if (!hit[i]) {
            if (r->nstale >= SPD_MAX)
                return die("z23-lint: too many stale rows to report\n", "");
            snprintf(r->stale[r->nstale++], sizeof r->stale[0], "%s",
                    base->row[i].key);
        }
    }
    return 0;
}

static int spd_write_update(const struct spd_counts *cur, const char *path)
{
    char rows[SPD_MAX][SPD_ROW];
    int n = 0;
    for (int i = 0; i < cur->n; i++) {
        int debt = cur->row[i].kids - cur->row[i].pol;
        if (debt < 0)
            debt = 0;
        if (debt <= 0)
            continue;
        if (n >= SPD_MAX)
            return die("z23-lint: derived buffer overflow\n", "");
        snprintf(rows[n++], sizeof rows[0], "%s %d", cur->row[i].path, debt);
    }
    qsort(rows, (size_t)n, SPD_ROW, spd_cmp);
    FILE *f = fopen(path, "w");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    if (fputs(
            "# check_supervisor_progress_declared baseline — files "
            "registering supervisor children with NO\n"
            "# progress-policy declaration (neither armed nor explicitly "
            "exempt).\n"
            "# Format: <path> <undeclared-count>.  COUNTS MAY ONLY "
            "SHRINK.\n#\n"
            "# Fix a row by giving each child a policy at its register "
            "site:\n"
            "#   supervisor_set_progress_max_quiet(id, <window_us>)  — "
            "armed, or\n"
            "#   supervisor_set_progress_exempt(id, \"why it has no work "
            "units\")\n"
            "# then lower (or delete) the number here. Adding a row is "
            "not a fix.\n"
            "# Regenerate: ZCL_LINT_MODE=UPDATE "
            "tools/lint/check_supervisor_progress_declared.sh\n",
            f) == EOF) {
        fclose(f);
        return die("z23-lint: write failed\n", "");
    }
    for (int i = 0; i < n; i++)
        if (fprintf(f, "%s\n", rows[i]) < 0) {
            fclose(f);
            return die("z23-lint: write failed\n", "");
        }
    if (fclose(f) != 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int spd_emit_pass(FILE *out, const struct spd_report *r,
                         int files_scanned, const struct spd_counts *cur,
                         int base_n)
{
    return fprintf(out,
                   "[check_supervisor_progress_declared] PASS (%d files, "
                   "%d registering file(s), %d child(ren), %d fully "
                   "declared, %d undeclared tolerated across %d of %d "
                   "baselined)\n",
                   files_scanned, cur->n, r->total_children,
                   r->declared_files, r->total_debt, r->tolerated,
                   base_n) < 0
               ? die("z23-lint: write failed\n", "")
               : 0;
}

static int spd_emit_fail(FILE *out, const struct spd_report *r)
{
    if (r->nviol > 0) {
        char rows[SPD_MAX][SPD_ROW + 64];
        memcpy(rows, r->viol, (size_t)r->nviol * sizeof rows[0]);
        qsort(rows, (size_t)r->nviol, sizeof rows[0], spd_cmp);
        if (fprintf(out,
                    "\n[check_supervisor_progress_declared] %d file(s) "
                    "register a supervised child with no\n"
                    "        progress policy — nothing would notice it "
                    "running forever\n"
                    "        without achieving anything:\n", r->nviol) < 0)
            return die("z23-lint: write failed\n", "");
        for (int i = 0; i < r->nviol; i++)
            if (fprintf(out, "  %s\n", rows[i]) < 0)
                return die("z23-lint: write failed\n", "");
        if (fputs(
                "\n  At the register site, declare ONE of:\n"
                "   1. supervisor_set_progress_max_quiet(id, <window_us>) "
                "— ARMED.\n"
                "      The child must then report supervisor_progress() "
                "when it does\n"
                "      work and supervisor_progress_idle() when it "
                "legitimately has\n"
                "      none. Do NOT report idle on an error or not-wired "
                "path: those\n"
                "      are exactly what the detector exists to catch.\n"
                "   2. supervisor_set_progress_exempt(id, \"why\") — "
                "EXEMPT, for a\n"
                "      child with no meaningful unit of work (a pure "
                "sampler, a\n"
                "      gauge publisher). The reason is shown to operators "
                "verbatim;\n"
                "      a blank one is refused by the primitive.\n"
                "  Worked example: "
                "engine/services/src/op_return_backfill_service.c\n"
                "  Raising a number in tools/lint/supervisor_progress_"
                "baseline.txt is NOT a fix; counts may only shrink.\n",
                out) == EOF)
            return die("z23-lint: write failed\n", "");
    }
    if (r->nstale > 0) {
        char rows[SPD_MAX][SPD_ROW];
        memcpy(rows, r->stale, (size_t)r->nstale * sizeof rows[0]);
        qsort(rows, (size_t)r->nstale, sizeof rows[0], spd_cmp);
        if (fprintf(out,
                    "\n[check_supervisor_progress_declared] %d STALE "
                    "baseline row(s) — the file no longer has\n"
                    "        undeclared children. Delete them from "
                    "tools/lint/supervisor_progress_baseline.txt:\n",
                    r->nstale) < 0)
            return die("z23-lint: write failed\n", "");
        for (int i = 0; i < r->nstale; i++)
            if (fprintf(out, "  %s\n", rows[i]) < 0)
                return die("z23-lint: write failed\n", "");
    }
    return 0;
}

static int spd_mode_valid(const char *m)
{
    return strcmp(m, "FAIL") == 0 || strcmp(m, "WARN") == 0
        || strcmp(m, "UPDATE") == 0;
}

static int spd_check(const struct spd_roots *roots, const char *base_path,
                     const char *mode, int file_floor, int child_floor,
                     FILE *out)
{
    struct spd_counts cur;
    cur.n = 0;
    struct spd_collect c = { roots, &cur, 0 };
    int files_scanned = 0;
    int rc = spd_collect(&c, &files_scanned);
    if (rc)
        return rc;
    rc = gate_require_scanned(files_scanned, file_floor,
                              "check_supervisor_progress_declared",
                              "no production .c under the scan roots");
    if (rc)
        return rc;
    rc = gate_require_scanned(cur.n, child_floor,
                              "check_supervisor_progress_declared",
                              "no liveness_contract_init() sites found — "
                              "the scan or the registration API moved");
    if (rc)
        return rc;
    if (strcmp(mode, "UPDATE") == 0)
        return spd_write_update(&cur, base_path);
    struct spd_baseline base;
    rc = spd_base_load(&base, base_path);
    if (rc)
        return rc;
    struct spd_report r;
    memset(&r, 0, sizeof r);
    rc = spd_classify(&r, &cur, &base);
    if (rc)
        return rc;
    if (r.nviol == 0 && r.nstale == 0)
        return spd_emit_pass(out, &r, files_scanned, &cur, base.n);
    rc = spd_emit_fail(out, &r);
    if (rc)
        return rc;
    return strcmp(mode, "FAIL") == 0 ? 1 : 0;
}

int check_supervisor_progress_declared_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    const char *mode = env_or("ZCL_LINT_MODE", "FAIL");
    if (!spd_mode_valid(mode))
        return die("z23-lint: ZCL_LINT_MODE must be FAIL, WARN, or UPDATE\n",
                   "");
    struct spd_roots roots;
    if (spd_parse_roots(env_or("ZCL_SUPERVISOR_PROGRESS_SCAN_ROOTS",
                               k_spd_roots_text), &roots))
        return 2;
    const char *base = env_or("ZCL_SUPERVISOR_PROGRESS_BASELINE",
                              k_spd_base_rel);
    const char *fenv = getenv("ZCL_SUPERVISOR_PROGRESS_FILE_FLOOR");
    const char *cenv = getenv("ZCL_SUPERVISOR_PROGRESS_CHILD_FLOOR");
    int file_floor = fenv && fenv[0] ? atoi(fenv) : 200;
    int child_floor = cenv && cenv[0] ? atoi(cenv) : 30;
    return spd_check(&roots, base, mode, file_floor, child_floor, stdout);
}

/* ── shared with the selftest sibling ─────────────────────────────────── */
int spd_run_for_selftest(FILE *out, int file_floor, int child_floor);
int spd_run_for_selftest(FILE *out, int file_floor, int child_floor)
{
    const char *mode = env_or("ZCL_LINT_MODE", "FAIL");
    struct spd_roots roots;
    if (spd_parse_roots(env_or("ZCL_SUPERVISOR_PROGRESS_SCAN_ROOTS",
                               k_spd_roots_text), &roots))
        return 2;
    const char *base = env_or("ZCL_SUPERVISOR_PROGRESS_BASELINE",
                              k_spd_base_rel);
    return spd_check(&roots, base, mode, file_floor, child_floor, out);
}
