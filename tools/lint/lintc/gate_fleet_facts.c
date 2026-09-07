/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-fleet-facts of the C23 lint runtime, the
 * replacement for tools/lint/check_fleet_facts.sh. engine/composition/
 * fleet_facts.def is the one place the fleet's doctrine is written down
 * (FLEET_TERM/FLEET_RELATION/FLEET_CONTEXT/FLEET_FACT rows); this gate
 * holds it internally consistent and holds docs/agent/EXECUTOR_HEURISTICS.md's
 * routing block to being this table's own rendered output (`--write-doc`,
 * `make docs-executor-routing`). A '/'-bearing term is checked against the
 * git index when one is present and the filesystem otherwise (dev/full
 * scan, or a hardlink sandbox with no .git). No file-scope mutable data —
 * state travels through explicit parameters. Selftest: gate_fleet_facts_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

enum {
    FF_ROWS = 4096, FF_FIELD = 320, FF_TOKMAX = 63, FF_WHYMAX = 223,
    FF_TERMCAP = 512, FF_FACTCAP = 512, FF_LINEBUF = 8192,
    FF_FAULTBUF = 262144, FF_DOCBUF = 262144, FF_BLOCKBUF = 65536
};

static const char k_ff_def_default[] = "engine/composition/fleet_facts.def";
static const char k_ff_doc_rel[] = "docs/agent/EXECUTOR_HEURISTICS.md";
static const char k_ff_begin[] = "<!-- FLEET-FACTS-ROUTING-BEGIN -->";
static const char k_ff_end[] = "<!-- FLEET-FACTS-ROUTING-END -->";
static const char k_ff_gate[] = "check_fleet_facts";

struct ff_row { char tag[16]; char f[6][FF_FIELD]; int nf; };

static int ff_is_start(const char *line, char *tag_out)
{
    static const char *const tags[] = { "RELATION", "CONTEXT", "TERM", "FACT" };
    if (strncmp(line, "FLEET_", 6) != 0)
        return 0;
    const char *p = line + 6;
    for (size_t i = 0; i < sizeof tags / sizeof tags[0]; i++) {
        size_t l = strlen(tags[i]);
        if (strncmp(p, tags[i], l) == 0 && p[l] == '(') {
            memcpy(tag_out, tags[i], l + 1);
            return 1;
        }
    }
    return 0;
}

static int ff_ends_here(const char *line)
{
    size_t n = strlen(line);
    while (n && isspace((unsigned char)line[n - 1])) n--;
    return n > 0 && line[n - 1] == ')';
}

static int ff_extract_strings(const char *buf, char out[][FF_FIELD], int maxn, int *n)
{
    *n = 0;
    for (const char *p = buf; *p; ) {
        if (*p != '"') { p++; continue; }
        const char *start = p + 1, *q = start;
        while (*q) {
            if (*q == '\\' && q[1]) { q += 2; continue; }
            if (*q == '"') break;
            q++;
        }
        if (*q != '"') { p++; continue; }
        size_t len = (size_t)(q - start);
        if (*n >= maxn || len >= FF_FIELD) return -1;
        memcpy(out[*n], start, len);
        out[*n][len] = '\0';
        (*n)++;
        p = q + 1;
    }
    return 0;
}

static int ff_close_row(const char *tag, const char *buf, struct ff_row *rows,
                        int cap, int *rn)
{
    char parts[8][FF_FIELD];
    int pn = 0;
    if (ff_extract_strings(buf, parts, 8, &pn) || *rn >= cap)
        return die("z23-lint: fleet-facts row overflow\n", "");
    int want = strcmp(tag, "FACT") == 0 ? 6 : 1;
    struct ff_row *r = &rows[*rn];
    if (pn != want) {
        memcpy(r->tag, "MALFORMED", 10);
        memcpy(r->f[0], tag, strlen(tag) + 1);
        r->nf = 1;
    } else {
        memcpy(r->tag, tag, strlen(tag) + 1);
        for (int i = 0; i < pn; i++)
            memcpy(r->f[i], parts[i], strlen(parts[i]) + 1);
        r->nf = pn;
    }
    (*rn)++;
    return 0;
}

/* Returns 0 ok, -1 ENOENT, -2 EACCES/other open failure, >0 die()'d rc. */
static int ff_parse_def(const char *path, struct ff_row *rows, int cap, int *out_n)
{
    FILE *f = fopen(path, "r");
    if (!f) return errno == EACCES ? -2 : -1;
    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    int collecting = 0, rc = 0, rn = 0;
    char tag[16] = "";
    static char buf[FF_LINEBUF];
    size_t buflen = 0;
    while (rc == 0 && (n = getline(&line, &lcap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';
        if (!collecting) {
            char t[16];
            if (!ff_is_start(line, t)) continue;
            collecting = 1;
            memcpy(tag, t, strlen(t) + 1);
            buflen = 0; buf[0] = '\0';
        }
        size_t ll = strlen(line);
        if (buflen + ll >= sizeof buf) {
            rc = die("z23-lint: fleet-facts source line too long\n", "");
            break;
        }
        memcpy(buf + buflen, line, ll);
        buflen += ll; buf[buflen] = '\0';
        if (ff_ends_here(line)) {
            collecting = 0;
            rc = ff_close_row(tag, buf, rows, cap, &rn);
        }
    }
    int ferr = ferror(f);
    free(line);
    fclose(f);
    *out_n = rn;
    if (rc) return rc;
    return ferr ? die("z23-lint: read failed: %s\n", path) : 0;
}

static void ff_counts(const struct ff_row *rows, int n, int *fact, int *term,
                      int *rel, int *ctx)
{
    *fact = *term = *rel = *ctx = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(rows[i].tag, "FACT") == 0) (*fact)++;
        else if (strcmp(rows[i].tag, "TERM") == 0) (*term)++;
        else if (strcmp(rows[i].tag, "RELATION") == 0) (*rel)++;
        else if (strcmp(rows[i].tag, "CONTEXT") == 0) (*ctx)++;
    }
}

/* term-is-a-tracked-path check: git index when present, filesystem else. */
struct ff_find { const char *want; int found; };
static int ff_find_cb(const char *path, int stage, void *ctx)
{
    (void)stage;
    struct ff_find *fd = ctx;
    if (strcmp(path, fd->want) == 0) fd->found = 1;
    return 0;
}

static int ff_tracked(const char *root, const char *rel)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd) || chdir(root) != 0) return -1;
    int have_git = access(".git", F_OK) == 0;
    int result;
    if (have_git) {
        struct ff_find fd = { rel, 0 };
        char badext[8];
        result = lint_git_index_foreach(ff_find_cb, &fd, badext) != 0 ? -1 : fd.found;
    } else {
        result = access(rel, F_OK) == 0;
    }
    if (chdir(cwd) != 0) return -1;
    return result;
}

/* string-set helpers (terms/relations/contexts) */
struct ff_strset { char v[FF_TERMCAP][FF_FIELD]; int n; };
static int ff_set_has(const struct ff_strset *s, const char *name)
{
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->v[i], name) == 0) return 1;
    return 0;
}
static int ff_set_add(struct ff_strset *s, const char *name)
{
    if (s->n >= FF_TERMCAP) return die("z23-lint: fleet-facts term-set overflow\n", "");
    memcpy(s->v[s->n], name, strlen(name) + 1);
    s->n++;
    return 0;
}
static int ff_collect(const struct ff_row *rows, int n, const char *tag,
                      struct ff_strset *out)
{
    out->n = 0;
    for (int i = 0; i < n; i++)
        if (strcmp(rows[i].tag, tag) == 0 && ff_set_add(out, rows[i].f[0]))
            return 2;
    return 0;
}
static int ff_strcmp_qs(const void *a, const void *b)
{ return strcmp((const char *)a, (const char *)b); }

/* Appends "  <msg>\n" once per value that occurs more than once in v[0..n). */
static int ff_report_dupes(char v[][FF_FIELD], int n, const char *fmt,
                           char *out, size_t cap, size_t *used)
{
    if (n == 0) return 0;
    qsort(v, (size_t)n, FF_FIELD, ff_strcmp_qs);
    for (int i = 1; i < n; i++) {
        if (strcmp(v[i], v[i - 1]) != 0) continue;
        if (i >= 2 && strcmp(v[i - 1], v[i - 2]) == 0) continue;
        char line[FF_FIELD + 64];
        if (ovf(snprintf(line, sizeof line, fmt, v[i]), sizeof line)) return 2;
        int k = snprintf(out + *used, cap - *used, "  %s\n", line);
        if (ovf(k, cap - *used)) return 2;
        *used += (size_t)k;
    }
    return 0;
}

static int ff_term_shape_ok(const char *name)
{
    unsigned char c0 = (unsigned char)name[0];
    if (!((c0 >= 'a' && c0 <= 'z') || (c0 >= '0' && c0 <= '9'))) return 0;
    for (const char *p = name + 1; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '.' || c == '_' || c == '/' || c == '-')) return 0;
    }
    return 1;
}

static int ff_append(char *out, size_t cap, size_t *used, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(out + *used, cap - *used, fmt, ap);
    va_end(ap);
    if (ovf(k, cap - *used)) return 2;
    *used += (size_t)k;
    return 0;
}

static int ff_check_one_term(const char *name, const char *root, char *out,
                             size_t cap, size_t *used)
{
    if (!ff_term_shape_ok(name))
        return ff_append(out, cap, used,
                         "  term '%s' is not a lowercase-rooted token or path\n", name);
    if (strlen(name) > FF_TOKMAX
        && ff_append(out, cap, used, "  term '%s' is longer than %d bytes\n",
                     name, FF_TOKMAX))
        return 2;
    if (!strchr(name, '/')) return 0;
    int t = ff_tracked(root, name);
    if (t < 0) return die("z23-lint: cannot probe tracked state under %s\n", root);
    if (!t)
        return ff_append(out, cap, used,
                         "  term '%s' looks like a path but is not tracked\n", name);
    return 0;
}
static int ff_check_terms(const struct ff_strset *terms, const char *root,
                          char *out, size_t cap, size_t *used)
{
    for (int i = 0; i < terms->n; i++)
        if (ff_check_one_term(terms->v[i], root, out, cap, used)) return 2;
    return 0;
}

static int ff_is_hex64(const char *s)
{
    size_t n = strlen(s);
    if (n != 64) return 0;
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)s[i]) || isupper((unsigned char)s[i])) return 0;
    return 1;
}

static int ff_check_fact_tokens(const struct ff_row *r, const struct ff_strset *terms,
                                char *out, size_t cap, size_t *used)
{
    const char *tok[2] = { r->f[0], r->f[2] };
    for (int i = 0; i < 2; i++) {
        if (ff_set_has(terms, tok[i]) || ff_is_hex64(tok[i])) continue;
        if (ff_append(out, cap, used,
                     "  '%s' is neither a declared term nor a canonical root\n", tok[i]))
            return 2;
    }
    return 0;
}
static int ff_check_fact_vocab(const struct ff_row *r, const struct ff_strset *rels,
                               const struct ff_strset *ctxs, char *out, size_t cap,
                               size_t *used)
{
    if (!ff_set_has(rels, r->f[1])
        && ff_append(out, cap, used, "  %s: relation '%s' is not declared\n",
                     r->f[0], r->f[1]))
        return 2;
    if (!ff_set_has(ctxs, r->f[3])
        && ff_append(out, cap, used, "  %s: context '%s' is not declared\n",
                     r->f[0], r->f[3]))
        return 2;
    return 0;
}
static int ff_check_fact_confidence_why(const struct ff_row *r, char *out,
                                        size_t cap, size_t *used)
{
    const char *conf = r->f[4], *why = r->f[5];
    if (strcmp(conf, "DOCTRINE") != 0 && strcmp(conf, "OBSERVED") != 0
        && ff_append(out, cap, used,
                     "  %s %s %s: confidence '%s' is not DOCTRINE or OBSERVED\n",
                     r->f[0], r->f[1], r->f[2], conf))
        return 2;
    int blank = 1;
    for (const char *p = why; *p; p++)
        if (!isspace((unsigned char)*p)) { blank = 0; break; }
    if (blank)
        return ff_append(out, cap, used, "  %s %s %s: empty why\n", r->f[0], r->f[1], r->f[2]);
    if (strlen(why) > FF_WHYMAX)
        return ff_append(out, cap, used, "  %s %s %s: why is longer than %d bytes\n",
                         r->f[0], r->f[1], r->f[2], FF_WHYMAX);
    return 0;
}
static int ff_check_one_fact(const struct ff_row *r, const struct ff_strset *terms,
                             const struct ff_strset *rels, const struct ff_strset *ctxs,
                             char *out, size_t cap, size_t *used)
{
    if (ff_check_fact_tokens(r, terms, out, cap, used)
        || ff_check_fact_vocab(r, rels, ctxs, out, cap, used)
        || ff_check_fact_confidence_why(r, out, cap, used))
        return 2;
    if (strcmp(r->f[1], "lives_at") == 0 && !strchr(r->f[2], '/')
        && ff_append(out, cap, used, "  %s lives_at '%s', which is not a path\n",
                     r->f[0], r->f[2]))
        return 2;
    return 0;
}
static int ff_check_facts(const struct ff_row *rows, int n, const struct ff_strset *terms,
                          const struct ff_strset *rels, const struct ff_strset *ctxs,
                          char *out, size_t cap, size_t *used)
{
    for (int i = 0; i < n; i++) {
        if (strcmp(rows[i].tag, "FACT") != 0) continue;
        if (ff_check_one_fact(&rows[i], terms, rels, ctxs, out, cap, used)) return 2;
    }
    return 0;
}

static int ff_check_duplicate_facts(const struct ff_row *rows, int n, char *out,
                                    size_t cap, size_t *used)
{
    static char keys[FF_FACTCAP][FF_FIELD];
    int kn = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(rows[i].tag, "FACT") != 0) continue;
        if (kn >= FF_FACTCAP)
            return die("z23-lint: fleet-facts fact-set overflow\n", "");
        if (ovf(snprintf(keys[kn], FF_FIELD, "%s|%s|%s|%s", rows[i].f[0], rows[i].f[1],
                         rows[i].f[2], rows[i].f[3]), FF_FIELD))
            return 2;
        kn++;
    }
    return ff_report_dupes(keys, kn, "a second row repeats '%s'", out, cap, used);
}

static int ff_check_unused_terms(const struct ff_row *rows, int n,
                                 const struct ff_strset *terms, char *out, size_t cap,
                                 size_t *used)
{
    struct ff_strset used_set = { .n = 0 };
    for (int i = 0; i < n; i++) {
        if (strcmp(rows[i].tag, "FACT") != 0) continue;
        if (!ff_set_has(&used_set, rows[i].f[0]) && ff_set_add(&used_set, rows[i].f[0]))
            return 2;
        if (!ff_set_has(&used_set, rows[i].f[2]) && ff_set_add(&used_set, rows[i].f[2]))
            return 2;
    }
    for (int i = 0; i < terms->n; i++)
        if (!ff_set_has(&used_set, terms->v[i])
            && ff_append(out, cap, used, "  term '%s' is declared but no row uses it\n",
                         terms->v[i]))
            return 2;
    return 0;
}

/* docs/agent/EXECUTOR_HEURISTICS.md routing block */
struct ff_docrow { char subj[FF_FIELD], rel[FF_FIELD], obj[FF_FIELD], why[FF_FIELD]; };
static int ff_docrow_cmp(const void *a, const void *b)
{
    const struct ff_docrow *x = a, *y = b;
    int c = strcmp(x->subj, y->subj);
    if (c) return c;
    c = strcmp(x->rel, y->rel);
    return c ? c : strcmp(x->obj, y->obj);
}
static int ff_handles(const char *rel) { return strncmp(rel, "handles_", 8) == 0; }

static int ff_emit_doc(const struct ff_row *rows, int n, char *out, size_t cap)
{
    struct ff_strset execs = { .n = 0 };
    for (int i = 0; i < n; i++)
        if (strcmp(rows[i].tag, "FACT") == 0 && ff_handles(rows[i].f[1])
            && !ff_set_has(&execs, rows[i].f[0]) && ff_set_add(&execs, rows[i].f[0]))
            return 2;
    static struct ff_docrow dr[FF_FACTCAP];
    int dn = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(rows[i].tag, "FACT") != 0) continue;
        const struct ff_row *r = &rows[i];
        if (!ff_set_has(&execs, r->f[0])) continue;
        if (!ff_handles(r->f[1]) && strcmp(r->f[1], "requires") != 0) continue;
        if (dn >= FF_FACTCAP)
            return die("z23-lint: fleet-facts doc-row overflow\n", "");
        memcpy(dr[dn].subj, r->f[0], strlen(r->f[0]) + 1);
        memcpy(dr[dn].rel, r->f[1], strlen(r->f[1]) + 1);
        memcpy(dr[dn].obj, r->f[2], strlen(r->f[2]) + 1);
        memcpy(dr[dn].why, r->f[5], strlen(r->f[5]) + 1);
        dn++;
    }
    qsort(dr, (size_t)dn, sizeof dr[0], ff_docrow_cmp);
    size_t used = 0;
    if (ff_append(out, cap, &used, "%s\n\n| Executor | Relation | Object | Why |\n"
                 "| --- | --- | --- | --- |\n", k_ff_begin))
        return 2;
    for (int i = 0; i < dn; i++)
        if (ff_append(out, cap, &used, "| %s | %s | %s | %s |\n", dr[i].subj, dr[i].rel,
                     dr[i].obj, dr[i].why))
            return 2;
    return ff_append(out, cap, &used, "\n%s\n", k_ff_end);
}

static int ff_slurp_all(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(out, 1, cap - 1, f);
    int bad = ferror(f);
    fclose(f);
    if (bad) return die("z23-lint: read failed: %s\n", path);
    out[n] = '\0';
    return 0;
}

/* Replaces the BEGIN..END marked span of doctext with block (which already
 * carries its own BEGIN/END lines). Sets *matched. */
static int ff_merge_doc(const char *doctext, const char *block, char *out,
                        size_t cap, int *matched)
{
    *matched = 0;
    size_t used = 0;
    int skip = 0;
    const char *p = doctext;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[FF_LINEBUF];
        if (n >= sizeof line) return die("z23-lint: doc line too long\n", "");
        memcpy(line, p, n);
        line[n] = '\0';
        if (!skip && strstr(line, k_ff_begin)) {
            skip = 1; *matched = 1;
            if (ff_append(out, cap, &used, "%s", block)) return 2;
        } else if (skip && strstr(line, k_ff_end)) {
            skip = 0;
        } else if (!skip) {
            if (ff_append(out, cap, &used, "%s\n", line)) return 2;
        }
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

static int ff_write_doc(const struct ff_row *rows, int n, const char *doc_path,
                        const char *doc_rel, const char *def_rel)
{
    static char docbuf[FF_DOCBUF], block[FF_BLOCKBUF], merged[FF_DOCBUF];
    if (ff_slurp_all(doc_path, docbuf, sizeof docbuf)) {
        fprintf(stderr, "[%s] FATAL — %s is missing\n", k_ff_gate, doc_path);
        return 2;
    }
    if (ff_emit_doc(rows, n, block, sizeof block)) return 2;
    int matched = 0;
    if (ff_merge_doc(docbuf, block, merged, sizeof merged, &matched)) return 2;
    if (!matched) {
        fprintf(stderr, "[%s] FATAL — %s carries no %s marker\n", k_ff_gate, doc_rel,
               k_ff_begin);
        return 2;
    }
    FILE *out = fopen(doc_path, "w");
    if (!out) return die("z23-lint: cannot open %s\n", doc_path);
    size_t len = strlen(merged);
    int bad = fwrite(merged, 1, len, out) != len;
    if (fclose(out) != 0 || bad) return die("z23-lint: write failed: %s\n", doc_path);
    printf("[%s] wrote the routing block in %s from %s\n", k_ff_gate, doc_rel, def_rel);
    return 0;
}

static int ff_resolve_root(char *out, size_t cap)
{
    const char *ov = env_or("ZCL_FLEET_FACTS_ROOT", "");
    if (ov[0]) return ovf(snprintf(out, cap, "%s", ov), cap);
    return cic_repo_root(out, cap);
}
static const char *ff_def_rel(void)
{ return env_or("ZCL_FLEET_FACTS_DEF", k_ff_def_default); }
static int ff_floor(void)
{
    const char *e = getenv("ZCL_FLEET_FACTS_FLOOR");
    return (e && e[0]) ? atoi(e) : 20;
}

static int ff_scan(const struct ff_row *rows, int n, const char *root, char *out,
                   size_t cap, size_t *used)
{
    int any_malformed = 0;
    for (int i = 0; i < n; i++)
        if (strcmp(rows[i].tag, "MALFORMED") == 0) { any_malformed = 1; break; }
    if (any_malformed
        && ff_append(out, cap, used, "  a row does not carry the right number of strings\n"))
        return 2;
    struct ff_strset terms = { .n = 0 }, rels = { .n = 0 }, ctxs = { .n = 0 };
    if (ff_collect(rows, n, "TERM", &terms) || ff_collect(rows, n, "RELATION", &rels)
        || ff_collect(rows, n, "CONTEXT", &ctxs))
        return 2;
    if (ff_check_terms(&terms, root, out, cap, used)) return 2;
    static char tcopy[FF_TERMCAP][FF_FIELD];
    memcpy(tcopy, terms.v, sizeof(char) * (size_t)terms.n * FF_FIELD);
    if (ff_report_dupes(tcopy, terms.n, "term '%s' is declared twice", out, cap, used))
        return 2;
    static char rc_copy[FF_TERMCAP][FF_FIELD];
    int rcn = 0;
    for (int i = 0; i < rels.n; i++) memcpy(rc_copy[rcn++], rels.v[i], FF_FIELD);
    for (int i = 0; i < ctxs.n; i++) memcpy(rc_copy[rcn++], ctxs.v[i], FF_FIELD);
    if (ff_report_dupes(rc_copy, rcn, "relation or context '%s' is declared twice",
                        out, cap, used))
        return 2;
    if (ff_check_facts(rows, n, &terms, &rels, &ctxs, out, cap, used)) return 2;
    if (ff_check_duplicate_facts(rows, n, out, cap, used)) return 2;
    return ff_check_unused_terms(rows, n, &terms, out, cap, used);
}

static int ff_scan_doc_block(const struct ff_row *rows, int n, const char *doc_path,
                             char *out, size_t cap, size_t *used)
{
    static char docbuf[FF_DOCBUF], block[FF_BLOCKBUF];
    if (ff_slurp_all(doc_path, docbuf, sizeof docbuf))
        return ff_append(out, cap, used,
                         "  %s is missing, so the routing block cannot be checked\n",
                         k_ff_doc_rel);
    if (ff_emit_doc(rows, n, block, sizeof block)) return 2;
    const char *b = strstr(docbuf, k_ff_begin);
    const char *e = b ? strstr(b, k_ff_end) : NULL;
    int match = 0;
    if (b && e) {
        size_t elen = (size_t)(e - b) + strlen(k_ff_end);
        size_t blen = strlen(block);
        /* block ends with "\n" + END_MARK + "\n"; compare without that
         * trailing newline, matching the doc slice which carries none. */
        match = blen > 0 && block[blen - 1] == '\n'
            && elen == blen - 1 && strncmp(b, block, elen) == 0;
    }
    if (match) return 0;
    return ff_append(out, cap, used,
                     "  %s's routing block is not this table's output\n"
                     "    fix with: make docs-executor-routing\n", k_ff_doc_rel);
}

static int ff_report_missing(const char *def)
{
    fprintf(stderr, "[%s] FATAL — %s is missing; refusing to report a clean scan\n",
           k_ff_gate, def);
    return 2;
}
static int ff_report_unreadable(const char *def)
{
    fprintf(stderr, "[%s] UNPROVEN — %s exists but is not readable; refusing to "
           "report a clean scan\n", k_ff_gate, def);
    return 2;
}
static int ff_report_floor(int fact_n, int term_n, int rel_n, int ctx_n, int floor)
{
    fprintf(stderr, "[%s] FATAL — %d facts, %d terms, %d relations, %d contexts is "
           "below the floor of %d facts and one of each vocabulary\n", k_ff_gate,
           fact_n, term_n, rel_n, ctx_n, floor);
    fputs("        A table that stopped parsing must never read as clean.\n", stderr);
    return 2;
}

int check_fleet_facts_run(int argc, char **argv)
{
    char root[4096], def[4096], doc[4096];
    if (ff_resolve_root(root, sizeof root)) return 2;
    const char *def_rel = ff_def_rel();
    if (ovf(snprintf(def, sizeof def, "%s/%s", root, def_rel), sizeof def)
        || ovf(snprintf(doc, sizeof doc, "%s/%s", root, k_ff_doc_rel), sizeof doc))
        return 2;

    static struct ff_row rows[FF_ROWS];
    int n = 0;
    int prc = ff_parse_def(def, rows, FF_ROWS, &n);
    if (prc == -1) return ff_report_missing(def);
    if (prc == -2) return ff_report_unreadable(def);
    if (prc) return prc;

    int fact_n, term_n, rel_n, ctx_n;
    ff_counts(rows, n, &fact_n, &term_n, &rel_n, &ctx_n);
    int floor = ff_floor();
    if (fact_n < floor || term_n < 1 || rel_n < 1 || ctx_n < 1)
        return ff_report_floor(fact_n, term_n, rel_n, ctx_n, floor);

    if (argc >= 1 && argv[0] && strcmp(argv[0], "--write-doc") == 0)
        return ff_write_doc(rows, n, doc, k_ff_doc_rel, def_rel);

    static char faults[FF_FAULTBUF];
    size_t used = 0;
    faults[0] = '\0';
    if (ff_scan(rows, n, root, faults, sizeof faults, &used)) return 2;
    if (ff_scan_doc_block(rows, n, doc, faults, sizeof faults, &used)) return 2;

    if (used > 0) {
        printf("[%s] FAIL — the fleet fact table has false rows:\n", k_ff_gate);
        fputs(faults, stdout);
        return 1;
    }
    printf("[%s] OK — %d facts over %d terms, %d relations and %d contexts; every "
          "term resolves and %s renders this table\n", k_ff_gate, fact_n, term_n,
          rel_n, ctx_n, k_ff_doc_rel);
    return 0;
}
