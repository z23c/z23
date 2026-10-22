/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-fleet-observations of the C23 lint runtime, the
 * replacement for tools/lint/lintc/gate_fleet_observations.c. engine/composition/
 * fleet_observations.def is GENERATED, never hand-typed: it reproduces
 * byte-for-byte from tests/fixtures/fleet_observations/rows.tsv through
 * build/bin/z23-fleet-observe --check, and the observed-routing block in
 * docs/agent/EXECUTOR_HEURISTICS.md is this .def's own rendered rows
 * (`--write-doc`, `make docs-executor-routing`).
 *
 * Env: ZCL_FLEET_OBS_ROOT, ZCL_FLEET_OBS_BIN, ZCL_FLEET_OBS_FIXTURE and
 * ZCL_FLEET_OBS_DEF override the repository root, the generator binary, the
 * fixture ledger and the committed .def. Exit: 0 clean, 1 when the .def or the
 * document block does not reproduce, 2 when an input is missing.
 * Selftest: gate_fleet_observations_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "gate_fleet_observations_priv.h"

const char k_fo_gate[] = "check_fleet_observations";
const char k_fo_doc_rel[] = "docs/agent/EXECUTOR_HEURISTICS.md";
static const char k_fo_begin[] = "<!-- FLEET-OBSERVATIONS-BEGIN -->";
static const char k_fo_end[] = "<!-- FLEET-OBSERVATIONS-END -->";

struct fo_parts {
    struct fo_buf v[8];
    size_t used;
};

struct fo_rows {
    char **v;
    size_t n, cap;
};

int fo_cfg_load(struct fo_cfg *c)
{
    const char *ov = env_or("ZCL_FLEET_OBS_ROOT", "");
    if (ov[0] ? ovf(snprintf(c->root, sizeof c->root, "%s", ov), sizeof c->root)
              : cic_repo_root(c->root, sizeof c->root))
        return 2;
    if (ovf(snprintf(c->bin, sizeof c->bin, "%s",
                     env_or("ZCL_FLEET_OBS_BIN", "build/bin/z23-fleet-observe")), sizeof c->bin)
        || ovf(snprintf(c->fixture, sizeof c->fixture, "%s",
                        env_or("ZCL_FLEET_OBS_FIXTURE",
                               "tests/fixtures/fleet_observations/rows.tsv")), sizeof c->fixture)
        || ovf(snprintf(c->def, sizeof c->def, "%s",
                        env_or("ZCL_FLEET_OBS_DEF",
                               "engine/composition/fleet_observations.def")), sizeof c->def)
        || ovf(snprintf(c->doc, sizeof c->doc, "%s/%s", c->root, k_fo_doc_rel), sizeof c->doc))
        return 2;
    if (chdir(c->root) != 0) {
        fprintf(stderr, "[%s] FATAL — cannot cd to %s\n", k_fo_gate, c->root);
        return 2;
    }
    return 0;
}

static int fo_is_file(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int fo_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

/* End index past the closing quote of the literal opening at s[i], or 0. */
static size_t fo_literal_end(const char *s, size_t n, size_t i)
{
    for (size_t j = i + 1; j < n; j++) {
        if (s[j] == '\\') {
            if (j + 1 >= n)
                return 0;
            j++;
        } else if (s[j] == '"') {
            return j + 1;
        }
    }
    return 0;
}

/* Quoted strings of one row, in order, into parts (earlier slots keep their
 * text when a row carries fewer strings, as the awk original did). Returns
 * the offset where the text after the last string begins. */
static size_t fo_take_strings(const char *s, size_t n, struct fo_parts *parts)
{
    size_t count = 0, rest = 0;
    for (size_t i = 0; i < n;) {
        size_t e = s[i] == '"' ? fo_literal_end(s, n, i) : 0;
        if (!e) {
            i++;
            continue;
        }
        if (count < 8) {
            parts->v[count].n = 0;
            fo_buf_put(&parts->v[count], s + i + 1, e - i - 2);
            if (count + 1 > parts->used)
                parts->used = count + 1;
        }
        count++;
        i = e;
        rest = e;
    }
    return rest;
}

/* Number after the commas of the row tail: field index 1..3 of the tail
 * split on ',' with parentheses removed (index 0 is the text before the
 * first comma), parsed the way awk's string-to-number does. */
static double fo_tail_number(const char *tail, size_t n, int idx)
{
    int field = 0;
    char num[64];
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        if (tail[i] == '(' || tail[i] == ')')
            continue;
        if (tail[i] == ',') {
            field++;
            continue;
        }
        if (field == idx && w + 1 < sizeof num)
            num[w++] = tail[i];
    }
    num[w] = '\0';
    return strtod(num, NULL);
}

static void fo_fmt_number(char *dst, size_t cap, double v)
{
    long long whole = (long long)v;
    if ((double)whole == v && whole > -1000000000000000LL && whole < 1000000000000000LL)
        snprintf(dst, cap, "%lld", whole);
    else
        snprintf(dst, cap, "%.6g", v);
}

static int fo_rows_add(struct fo_rows *r, const char *line, size_t n)
{
    if (r->n == r->cap) {
        size_t nc = r->cap ? r->cap * 2 : 64;
        char **nv = realloc(r->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv)
            return 1;
        r->v = nv;
        r->cap = nc;
    }
    char *copy = malloc(n + 1); // raw-alloc-ok:lint-runtime
    if (!copy)
        return 1;
    memcpy(copy, line, n);
    copy[n] = '\0';
    r->v[r->n++] = copy;
    return 0;
}

static int fo_row_close(const struct fo_buf *buf, struct fo_parts *parts, struct fo_rows *rows)
{
    size_t rest = fo_take_strings(buf->p, buf->n, parts);
    const char *tail = buf->p + rest;
    size_t tn = buf->n - rest;
    char num[40], den[40], win[40];
    fo_fmt_number(num, sizeof num, fo_tail_number(tail, tn, 1));
    fo_fmt_number(den, sizeof den, fo_tail_number(tail, tn, 2));
    fo_fmt_number(win, sizeof win, fo_tail_number(tail, tn, 3));
    struct fo_buf line = { 0 };
    for (int i = 0; i < 3; i++) {
        if (i < (int)parts->used)
            fo_buf_put(&line, parts->v[i].p ? parts->v[i].p : "", parts->v[i].n);
        fo_buf_puts(&line, "\t");
    }
    fo_buf_puts(&line, num);
    fo_buf_puts(&line, "/");
    fo_buf_puts(&line, den);
    fo_buf_puts(&line, "\t");
    fo_buf_puts(&line, win);
    int rc = line.err || fo_rows_add(rows, line.p, line.n);
    fo_buf_free(&line);
    return rc;
}

static int fo_ends_with_paren(const char *s, size_t n)
{
    while (n > 0 && fo_ws(s[n - 1]))
        n--;
    return n > 0 && s[n - 1] == ')';
}

/* The rows of a .def as tab-joined lines: executor, relation, task class,
 * num/den and window. */
static int fo_parse_def(const char *text, size_t len, struct fo_rows *rows)
{
    struct fo_parts parts = { 0 };
    struct fo_buf buf = { 0 };
    int collecting = 0, rc = 0;
    for (size_t pos = 0; pos < len && rc == 0;) {
        const char *nl = memchr(text + pos, '\n', len - pos);
        size_t ln = nl ? (size_t)(nl - (text + pos)) : len - pos;
        const char *line = text + pos;
        pos += ln + (nl ? 1 : 0);
        if (ln >= 15 && memcmp(line, "FLEET_OBSERVED(", 15) == 0) {
            collecting = 1;
            buf.n = 0;
        }
        if (!collecting)
            continue;
        fo_buf_put(&buf, line, ln);
        if (fo_ends_with_paren(line, ln)) {
            collecting = 0;
            rc = fo_row_close(&buf, &parts, rows);
        }
    }
    rc = rc || buf.err;
    for (size_t i = 0; i < 8; i++)
        fo_buf_free(&parts.v[i]);
    fo_buf_free(&buf);
    return rc;
}

static void fo_field(const char *s, int idx, const char **at, size_t *len)
{
    const char *p = s;
    for (int i = 0; i < idx; i++) {
        const char *t = strchr(p, '\t');
        if (!t) {
            *at = p + strlen(p);
            *len = 0;
            return;
        }
        p = t + 1;
    }
    const char *t = strchr(p, '\t');
    *at = p;
    *len = t ? (size_t)(t - p) : strlen(p);
}

static int fo_cmp_field(const char *a, const char *b, int idx)
{
    const char *pa, *pb;
    size_t la, lb;
    fo_field(a, idx, &pa, &la);
    fo_field(b, idx, &pb, &lb);
    int c = memcmp(pa, pb, la < lb ? la : lb);
    return c ? c : (la > lb) - (la < lb);
}

/* sort -t TAB -k1,1 -k3,3 -k2,2 under the C locale, ties by the whole line. */
static int fo_cmp_rows(const void *x, const void *y)
{
    const char *a = *(char *const *)x, *b = *(char *const *)y;
    int c = fo_cmp_field(a, b, 0);
    if (!c)
        c = fo_cmp_field(a, b, 2);
    if (!c)
        c = fo_cmp_field(a, b, 1);
    return c ? c : strcmp(a, b);
}

static void fo_put_row(struct fo_buf *out, const char *line)
{
    fo_buf_puts(out, "|");
    for (int i = 0; i < 5; i++) {
        const char *at;
        size_t len;
        fo_field(line, i, &at, &len);
        fo_buf_puts(out, " ");
        fo_buf_put(out, at, len);
        fo_buf_puts(out, " |");
    }
    fo_buf_puts(out, "\n");
}

/* The marker-delimited block rendered from the .def's own rows. */
int fo_render_doc(const char *def, struct fo_buf *out)
{
    struct fo_buf text = { 0 };
    struct fo_rows rows = { 0 };
    (void)fo_slurp(def, &text);
    int rc = fo_parse_def(text.p ? text.p : "", text.n, &rows);
    qsort(rows.v, rows.n, sizeof rows.v[0], fo_cmp_rows);
    fo_buf_puts(out, k_fo_begin);
    fo_buf_puts(out, "\n\n| Executor | Relation | Task class | n | window (days) |\n"
                     "| --- | --- | --- | --- | --- |\n");
    for (size_t i = 0; i < rows.n; i++) {
        fo_put_row(out, rows.v[i]);
        free(rows.v[i]);
    }
    fo_buf_puts(out, "\n");
    fo_buf_puts(out, k_fo_end);
    fo_buf_puts(out, "\n");
    free(rows.v);
    fo_buf_free(&text);
    return rc || out->err;
}

static int fo_line_has(const char *line, size_t n, const char *mark)
{
    size_t m = strlen(mark);
    for (size_t i = 0; i + m <= n; i++) {
        if (memcmp(line + i, mark, m) == 0)
            return 1;
    }
    return 0;
}

/* The document's marker-delimited lines, each newline-terminated. */
static void fo_doc_block(const char *doc, size_t len, struct fo_buf *out)
{
    int in = 0;
    for (size_t pos = 0; pos < len;) {
        const char *nl = memchr(doc + pos, '\n', len - pos);
        size_t ln = nl ? (size_t)(nl - (doc + pos)) : len - pos;
        const char *line = doc + pos;
        pos += ln + (nl ? 1 : 0);
        if (fo_line_has(line, ln, k_fo_begin))
            in = 1;
        if (in) {
            fo_buf_put(out, line, ln);
            fo_buf_puts(out, "\n");
        }
        if (fo_line_has(line, ln, k_fo_end))
            in = 0;
    }
}

/* The document with its block replaced by the rendered one. Returns 1 when
 * the document carried a begin marker. */
static int fo_merge_doc(const char *doc, size_t len, const struct fo_buf *block,
                        struct fo_buf *out)
{
    int skip = 0, found = 0, block_written = 0;
    for (size_t pos = 0; pos < len;) {
        const char *nl = memchr(doc + pos, '\n', len - pos);
        size_t ln = nl ? (size_t)(nl - (doc + pos)) : len - pos;
        const char *line = doc + pos;
        pos += ln + (nl ? 1 : 0);
        if (fo_line_has(line, ln, k_fo_begin)) {
            skip = 1;
            found = 1;
            if (!block_written)
                fo_buf_put(out, block->p, block->n);
            block_written = 1;
        } else if (skip && fo_line_has(line, ln, k_fo_end)) {
            skip = 0;
        } else if (!skip) {
            fo_buf_put(out, line, ln);
            fo_buf_puts(out, "\n");
        }
    }
    return found;
}

static int fo_replace_file(const char *path, const struct fo_buf *content)
{
    char tmp[FO_PATH + 16];
    struct stat st;
    if (stat(path, &st) != 0 || ovf(snprintf(tmp, sizeof tmp, "%s.XXXXXX", path), sizeof tmp))
        return 1;
    int fd = mkstemp(tmp);
    if (fd < 0)
        return 1;
    size_t done = 0;
    while (done < content->n) {
        ssize_t w = write(fd, content->p + done, content->n - done);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            break;
        done += (size_t)w;
    }
    int bad = done != content->n || fchmod(fd, st.st_mode & 07777) != 0;
    bad = close(fd) != 0 || bad || rename(tmp, path) != 0;
    if (bad)
        unlink(tmp);
    return bad;
}

static int fo_missing(const char *what, const char *tail)
{
    fprintf(stderr, "[%s] FATAL — %s is missing%s\n", k_fo_gate, what, tail);
    return 2;
}

static int fo_write_doc(const struct fo_cfg *c)
{
    if (!fo_is_file(c->def))
        return fo_missing(c->def, "");
    if (!fo_is_file(c->doc))
        return fo_missing(c->doc, "");
    struct fo_buf block = { 0 }, doc = { 0 }, merged = { 0 };
    int rc = fo_render_doc(c->def, &block);
    if (rc == 0 && fo_slurp(c->doc, &doc) != 0)
        rc = die("z23-lint: cannot read %s\n", c->doc);
    int found = rc == 0 && fo_merge_doc(doc.p ? doc.p : "", doc.n, &block, &merged);
    if (rc == 0 && !found) {
        fprintf(stderr, "[%s] FATAL — %s carries no %s marker\n", k_fo_gate, k_fo_doc_rel,
                k_fo_begin);
        rc = 2;
    } else if (rc == 0 && (merged.err || fo_replace_file(c->doc, &merged))) {
        rc = die("z23-lint: cannot write %s\n", c->doc);
    } else if (rc == 0) {
        printf("[%s] wrote the observed-routing block in %s from %s\n", k_fo_gate, k_fo_doc_rel,
               c->def);
    }
    fo_buf_free(&block);
    fo_buf_free(&doc);
    fo_buf_free(&merged);
    return rc;
}

/* 1 when the document's block is exactly the rendered table. */
static int fo_doc_matches(const struct fo_cfg *c)
{
    struct fo_buf want = { 0 }, doc = { 0 }, have = { 0 };
    int rc = fo_render_doc(c->def, &want);
    (void)fo_slurp(c->doc, &doc);
    fo_doc_block(doc.p ? doc.p : "", doc.n, &have);
    int same = rc == 0 && want.n == have.n && (want.n == 0 || memcmp(want.p, have.p, want.n) == 0);
    fo_buf_free(&want);
    fo_buf_free(&doc);
    fo_buf_free(&have);
    return same;
}

static void fo_chomp(struct fo_buf *b)
{
    while (b->n > 0 && b->p[b->n - 1] == '\n')
        b->p[--b->n] = '\0';
}

static int fo_generator_check(const struct fo_cfg *c, struct fo_buf *out, int *status)
{
    char ledger[FO_PATH + 16], days[] = "--days=7", outp[FO_PATH + 16], check[] = "--check";
    if (ovf(snprintf(ledger, sizeof ledger, "--ledger=%s", c->fixture), sizeof ledger)
        || ovf(snprintf(outp, sizeof outp, "--out=%s", c->def), sizeof outp))
        return 2;
    char *const argv[] = { (char *)c->bin, ledger, days, outp, check, NULL };
    *status = fo_run(c->bin, argv, out);
    if (*status == FO_SPAWN_FAILED) {
        fo_buf_puts(out, "cannot run the generator\n");
        *status = 127;
    }
    fo_chomp(out);
    return 0;
}

static int fo_fail_drift(const struct fo_cfg *c, const struct fo_buf *out)
{
    printf("[%s] FAIL — %s does not reproduce from %s:\n%s\n", k_fo_gate, c->def, c->fixture,
           out->p ? out->p : "");
    printf("  fix with: build/bin/z23-fleet-observe --ledger=%s --days=7 --out=%s\n", c->fixture,
           c->def);
    return 1;
}

static int fo_check(const struct fo_cfg *c)
{
    if (access(c->bin, X_OK) != 0) {
        fprintf(stderr, "[%s] FATAL — %s is missing; run 'make build-only' first\n", k_fo_gate,
                c->bin);
        return 2;
    }
    if (!fo_is_file(c->fixture)) {
        fprintf(stderr, "[%s] FATAL — fixture ledger %s is missing\n", k_fo_gate, c->fixture);
        return 2;
    }
    if (!fo_is_file(c->def)) {
        fprintf(stderr, "[%s] FATAL — %s is missing; refusing to report a clean scan\n",
                k_fo_gate, c->def);
        return 2;
    }
    struct fo_buf out = { 0 };
    int status = 0;
    int rc = fo_generator_check(c, &out, &status);
    if (rc == 0 && status == FO_INTERRUPTED)
        rc = 2;
    else if (rc == 0 && status != 0)
        rc = fo_fail_drift(c, &out);
    else if (rc == 0 && !fo_is_file(c->doc))
        rc = fo_missing(k_fo_doc_rel, ", so the observed-routing block cannot be checked");
    else if (rc == 0 && !fo_doc_matches(c)) {
        printf("[%s] FAIL — %s's observed-routing block is not this .def's own output\n"
               "  fix with: make docs-executor-routing\n", k_fo_gate, k_fo_doc_rel);
        rc = 1;
    } else if (rc == 0) {
        printf("[%s] OK — %s; %s renders this table\n", k_fo_gate, out.p ? out.p : "",
               k_fo_doc_rel);
    }
    fo_buf_free(&out);
    return rc;
}

int check_fleet_observations_run(int argc, char **argv)
{
    struct fo_cfg c;
    int rc = fo_cfg_load(&c);
    if (rc)
        return rc;
    struct fo_sigs sigs;
    fo_sigs_arm(&sigs);
    if (argc >= 1 && argv[0] && strcmp(argv[0], "--write-doc") == 0)
        rc = fo_write_doc(&c);
    else
        rc = fo_check(&c);
    fflush(stdout);
    return fo_finish(&sigs, rc);
}
