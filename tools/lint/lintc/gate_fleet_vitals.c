/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-fleet-vitals of the C23 lint runtime, the
 * replacement for tools/lint/check_fleet_vitals.sh. Holds the fleet vitals
 * catalog (engine/composition/fleet_vitals.def, the ONE declaration of what
 * a fleet metric is) closed, complete and identical to the table
 * docs/FLEET_LEDGER.md renders: every FLEET_VITAL row carries four strings
 * and an integer cadence, every id is unique and named, every unit and why
 * is non-empty, every agg is gauge or sum, and the doc table lists exactly
 * the catalog's ids in the catalog's own order. A hollow catalog (below the
 * floor) refuses with exit 2: a catalog that stopped parsing must never
 * read as clean. A metric id is IDENTITY — rows already signed carry its
 * position, so a silent edit re-points stored history at a different
 * metric.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_text.h"

/* Every static name carries the fv_ prefix: the code index links test
 * closures by symbol name. */

enum {
    FV_ROWS = 4096, FV_FIELD = 512, FV_LINEBUF = 16384,
    FV_IDS = 8192, FV_IDBUF = 512, FV_PATH = 8192
};

static const char k_fv_def_default[] = "engine/composition/fleet_vitals.def";
static const char k_fv_doc_default[] = "docs/FLEET_LEDGER.md";
static const char k_fv_gate[] = "check_fleet_vitals";

/* One parsed row. The five scan fields were joined TSV and re-split in the
 * script, so a quoted string containing a tab shifted the same columns both
 * times; fv_row keeps the post-split view. */
struct fv_row {
    char id[FV_FIELD], unit[FV_FIELD], agg[FV_FIELD];
    char cadence[FV_FIELD], why[FV_FIELD];
    bool malformed;
};

struct fv_ids { char v[FV_IDS][FV_IDBUF]; int n; };

/* Output sinks; the self-test silences both for its stub runs, exactly as
 * the script's >/dev/null 2>&1 did. */
static FILE *g_fv_out = NULL, *g_fv_err = NULL;

static void fv_out_line(const char *fmt, ...)
{
    va_list ap;
    if (!g_fv_out)
        return;
    va_start(ap, fmt);
    vfprintf(g_fv_out, fmt, ap);
    va_end(ap);
    fputc('\n', g_fv_out);
}

static void fv_err_line(const char *fmt, ...)
{
    va_list ap;
    if (!g_fv_err)
        return;
    va_start(ap, fmt);
    vfprintf(g_fv_err, fmt, ap);
    va_end(ap);
    fputc('\n', g_fv_err);
}

/* The script's awk string regex "([^"\\]|\\.)*": an escaped pair never ends
 * the literal. Returns 0 and fills out[0..*n), -1 on field overflow. */
static int fv_extract_strings(const char *buf, char out[][FV_FIELD],
                              int maxn, int *n)
{
    *n = 0;
    for (const char *p = buf; *p; ) {
        const char *start, *q;
        size_t len;
        if (*p != '"') { p++; continue; }
        start = p + 1;
        q = start;
        while (*q) {
            if (*q == '\\' && q[1]) { q += 2; continue; }
            if (*q == '"') break;
            q++;
        }
        if (*q != '"') { p++; continue; }
        len = (size_t)(q - start);
        if (*n >= maxn || len >= FV_FIELD) return -1;
        memcpy(out[*n], start, len);
        out[*n][len] = '\0';
        (*n)++;
        p = q + 1;
    }
    return 0;
}

/* Cadence: the first digit run in the row text with every quoted literal
 * removed — the script's gsub-then-match, not "the fourth argument". */
static void fv_find_cadence(const char *buf, char *out, size_t cap)
{
    size_t n = 0;
    out[0] = '\0';
    for (const char *p = buf; *p; ) {
        if (*p == '"') {
            p++;
            while (*p) {
                if (*p == '\\' && p[1]) { p += 2; continue; }
                if (*p == '"') { p++; break; }
                p++;
            }
            continue;
        }
        if (*p >= '0' && *p <= '9') {
            while (*p >= '0' && *p <= '9' && n + 1 < cap)
                out[n++] = *p++;
            out[n] = '\0';
            return;
        }
        p++;
    }
}

static bool fv_row_starts(const char *line)
{
    return strncmp(line, "FLEET_VITAL(", 12) == 0;
}

/* Join the four strings and the cadence TSV, then split the way the
 * script's `IFS=$'\t' read` did: tab is an IFS-whitespace character, so
 * leading and trailing tab runs are stripped and every RUN of tabs is ONE
 * delimiter — an empty string field therefore shifts every later field,
 * exactly as the script's read shifted them. The fifth field takes the
 * verbatim remainder. */
static void fv_row_fields(char parts[][FV_FIELD], const char *cadence,
                          struct fv_row *r)
{
    static char joined[FV_LINEBUF + 6 * FV_FIELD];
    char *f[5] = { r->id, r->unit, r->agg, r->cadence, r->why };
    const char *p;
    size_t used = 0;
    joined[0] = '\0';
    for (int i = 0; i < 4; i++) {
        const char *s = (i == 3) ? cadence : parts[i];
        used += (size_t)snprintf(joined + used, sizeof joined - used,
                                 "%s\t", s);
    }
    snprintf(joined + used, sizeof joined - used, "%s", parts[3]);
    p = joined;
    while (*p == '\t') p++;
    for (int i = 0; i < 5; i++) {
        const char *start = p, *end;
        if (i == 4) {
            end = p + strlen(p);
            while (end > start && end[-1] == '\t') end--;
        } else {
            while (*p && *p != '\t') p++;
            end = p;
            while (*p == '\t') p++;
        }
        size_t len = (size_t)(end - start);
        if (len >= FV_FIELD) len = FV_FIELD - 1;
        memcpy(f[i], start, len);
        f[i][len] = '\0';
    }
}

/* Close one collected row: extract, cadence, TSV-split — or MALFORMED. */
static void fv_close_row(const char *buf, struct fv_row *r)
{
    char parts[8][FV_FIELD];
    char cadence[FV_FIELD];
    int np = 0;
    r->malformed = false;
    if (fv_extract_strings(buf, parts, 8, &np) != 0)
        r->malformed = true;
    fv_find_cadence(buf, cadence, sizeof cadence);
    if (np != 4 || cadence[0] == '\0')
        r->malformed = true;
    else
        fv_row_fields(parts, cadence, r);
    if (r->malformed)
        r->id[0] = r->unit[0] = r->agg[0] = r->cadence[0]
            = r->why[0] = '\0';
}

/* Parse the catalog. Returns 0 ok, >0 die rc, -1 missing, -2 unreadable.
 * A row still open at EOF is dropped silently, and a new FLEET_VITAL(
 * restarts the buffer — both exactly as the awk collected. */
static int fv_parse(const char *path, struct fv_row *rows, int cap, int *rn)
{
    FILE *f = fopen(path, "r");
    static char buf[FV_LINEBUF];
    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    int collecting = 0, rc = 0;
    size_t buflen = 0;
    *rn = 0;
    if (!f) return errno == EACCES ? -2 : -1;
    while (rc == 0 && (n = getline(&line, &lcap, f)) >= 0) {
        size_t ll;
        if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';
        if (fv_row_starts(line)) {
            collecting = 1;
            buflen = 0;
            buf[0] = '\0';
        }
        if (!collecting) continue;
        ll = strlen(line);
        if (buflen + ll >= sizeof buf) {
            rc = die("z23-lint: fleet-vitals row text too long\n", "");
            break;
        }
        memcpy(buf + buflen, line, ll);
        buflen += ll;
        buf[buflen] = '\0';
        if (!lct_ends_with_paren(line)) continue;
        collecting = 0;
        if (*rn >= cap) {
            rc = die("z23-lint: fleet-vitals row overflow\n", "");
            break;
        }
        fv_close_row(buf, &rows[(*rn)++]);
    }
    n = ferror(f) ? 1 : 0;
    free(line);
    fclose(f);
    if (rc) return rc;
    return n ? die("z23-lint: read failed: %s\n", path) : 0;
}

static int fv_append_fault(char *out, size_t cap, size_t *used,
                           const char *fmt, const char *a, const char *b)
{
    int k = snprintf(out + *used, cap - *used, fmt, a, b ? b : "");
    if (k < 0 || (size_t)k >= cap - *used)
        return die("z23-lint: fleet-vitals fault buffer overflow\n", "");
    *used += (size_t)k;
    return 0;
}

/* One row's checks, in the script's order: duplicate, unit, agg, cadence,
 * why. A duplicate still checks the rest of the row. */
static int fv_scan_row(const struct fv_row *rows, int i,
                       char *out, size_t cap, size_t *used)
{
    const struct fv_row *r = &rows[i];
    for (int k = 0; k < i; k++)
        if (rows[k].id[0] && strcmp(rows[k].id, r->id) == 0) {
            if (fv_append_fault(out, cap, used,
                    "  %s: a second row for an id that already has one\n",
                    r->id, NULL))
                return 2;
            break;
        }
    if (r->unit[0] == '\0' && fv_append_fault(out, cap, used,
            "  %s: empty unit \xE2\x80\x94 an integer with no unit is not "
            "a measurement\n", r->id, NULL))
        return 2;
    if (strcmp(r->agg, "gauge") != 0 && strcmp(r->agg, "sum") != 0
        && fv_append_fault(out, cap, used,
            "  %s: agg '%s' is neither gauge nor sum\n", r->id, r->agg))
        return 2;
    if (!lct_is_digits(r->cadence) && fv_append_fault(out, cap, used,
            "  %s: cadence '%s' is not a non-negative integer\n",
            r->id, r->cadence))
        return 2;
    if (r->why[0] == '\0' && fv_append_fault(out, cap, used,
            "  %s: empty why \xE2\x80\x94 nobody can say what the number "
            "is for\n", r->id, NULL))
        return 2;
    return 0;
}

static int fv_scan(const struct fv_row *rows, int n, char *out, size_t cap)
{
    size_t used = 0;
    out[0] = '\0';
    for (int i = 0; i < n; i++) {
        int k;
        if (rows[i].malformed) {
            k = snprintf(out + used, cap - used,
                "  a FLEET_VITAL row does not carry four strings and a "
                "cadence\n");
            if (ovf(k, cap - used)) return 2;
            used += (size_t)k;
            continue;
        }
        if (rows[i].id[0] == '\0') continue;
        if (fv_scan_row(rows, i, out, cap, &used)) return 2;
    }
    return 0;
}

/* The id span [a-z]+\.[a-z0-9_]+ starting at p: on match *e points just
 * past the span and true is returned. */
static bool fv_id_span(const char *p, const char **e)
{
    int letters = 0, tail = 0;
    while (*p >= 'a' && *p <= 'z') { p++; letters++; }
    if (letters == 0 || *p++ != '.') return false;
    while ((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9')
        || *p == '_') { p++; tail++; }
    if (tail == 0) return false;
    *e = p;
    return true;
}

/* The doc table row shape, minus extraction: '|' spaces '`' id '`' spaces
 * '|', with the id [a-z]+\.[a-z0-9_]+ — exactly the awk regex. On match
 * the id span is left in *b..*e. */
static bool fv_doc_shape(const char *line, const char **b, const char **e)
{
    const char *p = line;
    if (*p++ != '|') return false;
    while (*p == ' ' || *p == '\t') p++;
    if (*p++ != '`') return false;
    *b = p;
    if (!fv_id_span(p, e)) return false;
    p = *e;
    if (*p++ != '`') return false;
    while (*p == ' ' || *p == '\t') p++;
    return *p == '|';
}

/* One doc row: shape check then copy the id span. */
static bool fv_doc_id(const char *line, char *id, size_t cap)
{
    const char *b = NULL, *e = NULL;
    size_t len;
    if (!fv_doc_shape(line, &b, &e)) return false;
    len = (size_t)(e - b);
    if (len + 1 > cap) return false;
    memcpy(id, b, len);
    id[len] = '\0';
    return true;
}

static int fv_doc_ids(const char *path, struct fv_ids *ids)
{
    FILE *f = fopen(path, "r");
    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    ids->n = 0;
    if (!f) return errno == EACCES ? -2 : -1;
    while ((n = getline(&line, &lcap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        if (ids->n >= FV_IDS) {
            free(line);
            fclose(f);
            return die("z23-lint: fleet-vitals doc table too large\n", "");
        }
        if (fv_doc_id(line, ids->v[ids->n], FV_IDBUF))
            ids->n++;
    }
    n = ferror(f) ? 1 : 0;
    free(line);
    fclose(f);
    return n ? die("z23-lint: read failed: %s\n", path) : 0;
}

/* ── the drift report: the real diff, capped at 40 lines like head -40 ───
 *
 * The script's report WAS `diff <(def_ids) <(rendered) | head -40`. GNU
 * diff's exact hunk addresses are part of the output this gate promised,
 * so the port runs diff(1) itself through capture_cmd (the same seam
 * rap_rm_rf uses) on two temp id lists, and prints at most the first 40
 * lines. An empty list still writes one empty line — the artifact of the
 * script's printf '%s\n' "$var" over an empty string — because the awk
 * comparison saw exactly that. */

static int fv_write_ids(const char *path, char const *const *ids, int n)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    if (n == 0) {
        fputc('\n', f);
    } else {
        for (int i = 0; i < n; i++)
            fprintf(f, "%s\n", ids[i]);
    }
    return fclose(f) == 0 ? 0 : -1;
}

/* Prints at most 40 lines of a captured diff; returns 0 on success. The
 * capture strips a trailing newline, so a final line without one gets it
 * back — head -40 always emitted complete lines. */
static int fv_print_capped(const char *text)
{
    int lines = 0;
    const char *p = text;
    if (!g_fv_out)
        return 0;
    while (*p && lines < 40) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) + 1 : strlen(p);
        fwrite(p, 1, len, g_fv_out);
        if (!nl)
            fputc('\n', g_fv_out);
        lines++;
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

static int fv_diff_lists(char const *const *a, int na,
                         char const *const *b, int nb)
{
    static char buf[262144];
    char pa[4096], pb[4096];
    char cmd[8192];
    int fd_a, fd_b, code, rc;
    const char *tmp = env_or("TMPDIR", "/tmp");
    snprintf(pa, sizeof pa, "%s/fv-def-ids-XXXXXX", tmp);
    snprintf(pb, sizeof pb, "%s/fv-doc-ids-XXXXXX", tmp);
    fd_a = mkstemp(pa);
    if (fd_a < 0)
        return die("z23-lint: fleet-vitals diff fixture failed\n", "");
    fd_b = mkstemp(pb);
    if (fd_b < 0) {
        close(fd_a);
        unlink(pa);
        return die("z23-lint: fleet-vitals diff fixture failed\n", "");
    }
    rc = 0;
    if (fv_write_ids(pa, a, na) != 0 || fv_write_ids(pb, b, nb) != 0
        || ovf(snprintf(cmd, sizeof cmd, "diff '%s' '%s'", pa, pb),
               sizeof cmd))
        rc = die("z23-lint: fleet-vitals diff fixture failed\n", "");
    if (!rc && capture_cmd(cmd, buf, sizeof buf, &code) != 0)
        rc = 2;
    if (!rc)
        fv_print_capped(buf);
    close(fd_a);
    close(fd_b);
    unlink(pa);
    unlink(pb);
    return rc;
}

/* ── the scan ──────────────────────────────────────────────────────────── */

static const char *fv_def_rel(void)
{ return env_or("ZCL_FLEET_VITALS_DEF", k_fv_def_default); }
static const char *fv_doc_rel(void)
{ return env_or("ZCL_FLEET_VITALS_DOC", k_fv_doc_default); }
static int fv_floor(void)
{
    const char *e = getenv("ZCL_FLEET_VITALS_FLOOR");
    return (e && e[0]) ? atoi(e) : 30;
}

/* The doc table must list exactly the catalog's ids in catalog order. An
 * empty side compares as one empty line — the artifact of the script's
 * printf '%s\n' over an empty string, which the diff saw too. */
static int fv_compare_doc(const struct fv_ids *doc, char def_ids[][FV_IDBUF],
                          int n, const char *def_rel, const char *doc_rel)
{
    static const char *a[FV_ROWS];
    static const char *b[FV_IDS];
    static const char *empty = "";
    int na = n, nb = doc->n;
    bool same = doc->n == n;
    for (int i = 0; same && i < n; i++)
        if (strcmp(def_ids[i], doc->v[i]) != 0) same = false;
    if (same) return 0;
    fv_out_line("[%s] FAIL \xE2\x80\x94 %s's vitals table is not %s, "
                "in order:", k_fv_gate, doc_rel, def_rel);
    for (int i = 0; i < n; i++) a[i] = def_ids[i];
    for (int i = 0; i < doc->n; i++) b[i] = doc->v[i];
    if (na == 0) a[na++] = empty;
    if (nb == 0) b[nb++] = empty;
    if (fv_diff_lists(a, na, b, nb)) return 2;
    fv_out_line("        Regenerate the table from the catalog; never "
                "edit one alone.");
    return 1;
}

/* Both inputs must exist: a hollow scan must never read as clean. */
static int fv_paths_ok(const char *def_path, const char *doc_path)
{
    if (access(def_path, F_OK) != 0) {
        fv_err_line("[%s] FATAL \xE2\x80\x94 %s is missing; refusing to "
                    "report a clean scan", k_fv_gate, def_path);
        return 2;
    }
    if (access(doc_path, F_OK) != 0) {
        fv_err_line("[%s] FATAL \xE2\x80\x94 %s is missing; the rendered "
                    "table cannot be checked", k_fv_gate, doc_path);
        return 2;
    }
    return 0;
}

/* Load the doc table and compare it to the catalog ids, or FATAL. */
static int fv_doc_stage(const char *doc_path, char id_store[][FV_IDBUF],
                        int n, const char *def_rel, const char *doc_rel)
{
    static struct fv_ids doc;
    int rc = fv_doc_ids(doc_path, &doc);
    if (rc > 0) return rc;
    if (rc < 0) {
        fv_err_line("[%s] FATAL \xE2\x80\x94 %s is missing; the rendered "
                    "table cannot be checked", k_fv_gate, doc_path);
        return 2;
    }
    return fv_compare_doc(&doc, id_store, n, def_rel, doc_rel);
}

static int fv_check(const char *root, const char *def_rel,
                    const char *doc_rel, int floor)
{
    static struct fv_row rows[FV_ROWS];
    static char def_path[FV_PATH], doc_path[FV_PATH];
    static char faults[FV_LINEBUF * 4];
    static char id_store[FV_ROWS][FV_IDBUF];
    int n = 0, rc;
    if (ovf(snprintf(def_path, sizeof def_path, "%s/%s", root, def_rel),
            sizeof def_path)
        || ovf(snprintf(doc_path, sizeof doc_path, "%s/%s", root, doc_rel),
               sizeof doc_path))
        return die("z23-lint: fleet-vitals path too long\n", "");
    if (access(def_path, F_OK) != 0 || access(doc_path, F_OK) != 0)
        return fv_paths_ok(def_path, doc_path);
    rc = fv_parse(def_path, rows, FV_ROWS, &n);
    if (rc > 0) return rc;
    if (rc < 0) {
        fv_err_line("[%s] FATAL \xE2\x80\x94 %s is missing; refusing to "
                    "report a clean scan", k_fv_gate, def_path);
        return 2;
    }
    if (n < floor) {
        fv_err_line("[%s] FATAL \xE2\x80\x94 %d vitals rows is below the "
                    "floor of %d", k_fv_gate, n, floor);
        fv_err_line("        A catalog that stopped parsing must never read "
                    "as clean.");
        return 2;
    }
    rc = fv_scan(rows, n, faults, sizeof faults);
    if (rc) return rc;
    if (faults[0]) {
        fv_out_line("[%s] FAIL \xE2\x80\x94 the vitals catalog has false "
                    "rows:", k_fv_gate);
        if (g_fv_out)
            fputs(faults, g_fv_out);
        return 1;
    }
    for (int i = 0; i < n; i++) {
        size_t len = strlen(rows[i].id);
        if (len >= FV_IDBUF) len = FV_IDBUF - 1;
        memcpy(id_store[i], rows[i].id, len);
        id_store[i][len] = '\0';
    }
    rc = fv_doc_stage(doc_path, id_store, n, def_rel, doc_rel);
    if (rc) return rc;
    fv_out_line("[%s] OK \xE2\x80\x94 %d vitals; every id unique, every "
                "unit and why named, every agg in the enum, and %s renders "
                "exactly this list", k_fv_gate, n, doc_rel);
    return 0;
}

/* ── self-test ─────────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_fv_signal;
static char g_fv_tmp[4096];

static void fv_on_signal(int sig)
{
    g_fv_signal = sig;
}

/* Cleanup with the recorded signal delivered afterwards: the handler only
 * records, removal runs with signals blocked, then the disposition is
 * restored and the signal re-raised, as the EXIT trap's cleanup did. */
static void fv_cleanup_and_raise(void)
{
    int sig = (int)g_fv_signal;
    sigset_t all, old;
    sigfillset(&all);
    sigprocmask(SIG_BLOCK, &all, &old);
    if (g_fv_tmp[0]) {
        rap_rm_rf(g_fv_tmp);
        g_fv_tmp[0] = '\0';
    }
    if (sig) {
        signal(sig, SIG_DFL);
        sigprocmask(SIG_SETMASK, &old, NULL);
        raise(sig);
        _exit(128 + sig);
    }
    sigprocmask(SIG_SETMASK, &old, NULL);
}

static int fv_write(const char *rel, const char *text)
{
    char path[4096];
    FILE *f;
    if (snprintf(path, sizeof path, "%s/%s", g_fv_tmp, rel)
        >= (int)sizeof path)
        return -1;
    f = fopen(path, "w");
    if (!f) return -1;
    fputs(text, f);
    return fclose(f) == 0 ? 0 : -1;
}

/* The stub run: the script re-invoked itself with env overrides; the gate
 * runs its own check with the same parameters and both streams silenced. */
static int fv_stub(const char *def_rel, const char *doc_rel, int floor)
{
    FILE *saved_out = g_fv_out, *saved_err = g_fv_err;
    int rc;
    g_fv_out = NULL;
    g_fv_err = NULL;
    rc = fv_check(g_fv_tmp, def_rel, doc_rel, floor);
    g_fv_out = saved_out;
    g_fv_err = saved_err;
    return rc;
}

static int fv_selftest_setup(void)
{
    struct sigaction sa;
    sigset_t block, old;
    char template[4096];
    char sub[4096];
    const char *tmp;
    char *dir;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = fv_on_signal;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGTERM);
    sa.sa_flags = 0;              /* no SA_RESTART, no SA_RESETHAND */
    if (sigaction(SIGINT, &sa, NULL) != 0
        || sigaction(SIGTERM, &sa, NULL) != 0)
        return -1;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    sigprocmask(SIG_BLOCK, &block, &old);
    tmp = env_or("TMPDIR", "/tmp");
    if (snprintf(template, sizeof template, "%s/zcl-fleet-vitals.XXXXXX",
                 tmp) >= (int)sizeof template) {
        sigprocmask(SIG_SETMASK, &old, NULL);
        return -1;
    }
    dir = mkdtemp(template);
    if (!dir) {
        sigprocmask(SIG_SETMASK, &old, NULL);
        return -1;
    }
    snprintf(g_fv_tmp, sizeof g_fv_tmp, "%s", dir);
    sigprocmask(SIG_SETMASK, &old, NULL);
    /* The script's mkdir -p: build each parent as well. */
    if (snprintf(sub, sizeof sub, "%s/engine", g_fv_tmp) >= (int)sizeof sub)
        return -1;
    if (mkdir(sub, 0755) != 0 && errno != EEXIST) return -1;
    if (snprintf(sub, sizeof sub, "%s/engine/composition", g_fv_tmp)
        >= (int)sizeof sub)
        return -1;
    if (mkdir(sub, 0755) != 0 && errno != EEXIST) return -1;
    if (snprintf(sub, sizeof sub, "%s/docs", g_fv_tmp) >= (int)sizeof sub)
        return -1;
    if (mkdir(sub, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* One expecting-failure case: writes def+doc, requires a nonzero rc. */
static int fv_case_reject(const char *def, const char *doc,
                          const char *ok, const char *fail)
{
    if (fv_write("engine/composition/fleet_vitals.def", def) == 0
        && fv_write("docs/FLEET_LEDGER.md", doc) == 0
        && fv_stub("engine/composition/fleet_vitals.def",
                   "docs/FLEET_LEDGER.md", 1) != 0) {
        fv_out_line("  selftest ok: %s", ok);
        return 0;
    }
    fv_err_line("%s: SELFTEST FAILED \xE2\x80\x94 %s", k_fv_gate, fail);
    return 1;
}

int check_fleet_vitals_selftest(void)
{
    /* The lint dispatcher can reach this entry point directly; the sinks
     * must never stay NULL here. */
    if (!g_fv_out) g_fv_out = stdout;
    if (!g_fv_err) g_fv_err = stderr;
    {
    static const char good_def[] =
        "FLEET_VITAL(\"box.load1\", \"load\", \"gauge\", 300, "
        "\"room for a lane\")\n";
    static const char good_doc[] =
        "| id | unit | agg |\n| --- | --- | --- |\n"
        "| `box.load1` | count | sum |\n";
    static const char dup_def[] =
        "FLEET_VITAL(\"box.load1\", \"load\", \"gauge\", 300, \"a\")\n"
        "FLEET_VITAL(\"box.load1\", \"load\", \"sum\", 5, \"b\")\n";
    static const char dup_doc[] =
        "| id | unit | agg |\n| --- | --- | --- |\n"
        "| `box.load1` | count | sum |\n"
        "| `box.load1` | count | sum |\n";
    static const char unit_def[] =
        "FLEET_VITAL(\"box.load1\", \"\", \"gauge\", 300, \"a\")\n";
    static const char agg_def[] =
        "FLEET_VITAL(\"box.load1\", \"load\", \"average\", 300, \"a\")\n";
    static const char drift_doc[] =
        "| id | unit | agg |\n| --- | --- | --- |\n"
        "| `box.cores` | count | sum |\n";
    int fails = 0, rc;
    if (fv_selftest_setup() != 0) {
        fv_err_line("%s: SELFTEST FAILED \xE2\x80\x94 cannot create the "
                    "fixture tree", k_fv_gate);
        return 1;
    }
    if (g_fv_signal) { fv_cleanup_and_raise(); return 1; }

    if (fv_write("engine/composition/fleet_vitals.def", good_def) == 0
        && fv_write("docs/FLEET_LEDGER.md", good_doc) == 0
        && fv_stub("engine/composition/fleet_vitals.def",
                   "docs/FLEET_LEDGER.md", 1) == 0)
        fv_out_line("  selftest ok: a complete row with a matching doc "
                    "table");
    else {
        fv_err_line("%s: SELFTEST FAILED \xE2\x80\x94 a sound catalog did "
                    "not pass", k_fv_gate);
        fails++;
    }
    if (g_fv_signal) { fv_cleanup_and_raise(); return 1; }
    fails += fv_case_reject(dup_def, dup_doc, "a duplicate id",
                            "a duplicate id passed");
    if (g_fv_signal) { fv_cleanup_and_raise(); return 1; }
    fails += fv_case_reject(unit_def, good_doc, "an empty unit",
                            "an empty unit passed");
    if (g_fv_signal) { fv_cleanup_and_raise(); return 1; }
    fails += fv_case_reject(agg_def, good_doc, "an agg outside the enum",
                            "an agg outside the enum passed");
    if (g_fv_signal) { fv_cleanup_and_raise(); return 1; }
    fails += fv_case_reject(good_def, drift_doc,
                            "a doc table that names a different id",
                            "a drifted doc table passed");
    rc = fv_stub("missing.def", "docs/FLEET_LEDGER.md", 1);
    if (rc == 2)
        fv_out_line("  selftest ok: a missing .def exits 2");
    else {
        fv_err_line("%s: SELFTEST FAILED \xE2\x80\x94 a missing .def did "
                    "not exit 2 (rc=%d)", k_fv_gate, rc);
        fails++;
    }
    fv_cleanup_and_raise();
    if (fails) return 1;
    fv_out_line("[%s] SELFTEST PASS (duplicate id, empty unit, unknown agg "
                "and a drifted doc table all fail; a sound catalog passes; "
                "a missing .def exits 2)", k_fv_gate);
    return 0;
    }
}

int check_fleet_vitals_run(int argc, char **argv)
{
    static char root[FV_PATH];
    const char *ov = getenv("ZCL_FLEET_VITALS_ROOT");
    g_fv_out = stdout;
    g_fv_err = stderr;
    if (argc >= 1 && strcmp(argv[0], "--selftest") == 0)
        return check_fleet_vitals_selftest();
    if (ov && ov[0])
        snprintf(root, sizeof root, "%s", ov);
    else if (cic_repo_root(root, sizeof root))
        return die("z23-lint: cannot find the repo root\n", "");
    return fv_check(root, fv_def_rel(), fv_doc_rel(), fv_floor());
}
