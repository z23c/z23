/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-api-reference-generated. The command reference
 * is GENERATED (build/gen/API_REFERENCE.md, not tracked): the gate compiles
 * tools/gen_api_reference.c, runs it over docs/API_REFERENCE.md.in into
 * build/gen, then proves the output is complete: every heading of the template
 * is present, no generation marker is left unexpanded, and every command leaf
 * declared in the .def catalogs has a row. There is no stored copy to drift
 * from; a doc that names a `ready` command that is `planned` cannot exist
 * because the page is rebuilt from the catalog every time.
 *
 * The scan set is exactly what the generator #includes, not a glob of the
 * commands directory: a glob misses the nested bundles and counts .def files
 * the generator never reads. No make is invoked and nothing here reads git.
 *
 * To fix a failure: edit a .def under engine/composition/commands,
 * docs/API_REFERENCE.md.in or the generator, then run `make docs-api-reference`.
 * The selftest lives in gate_api_reference_generated_selftest.c.
 *
 * Exit codes: 0 clean, 1 incomplete, 2 fatal. The scratch directory is removed
 * on every path; a termination signal is recorded, the directory is removed,
 * and the signal is re-raised with its default disposition.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <limits.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "gate_api_reference_generated_priv.h"
#include "lintc.h"
#include "lintc_proc.h"
#include "lintc_sig.h"

enum { ARG_FLOOR_DEFS = 20, ARG_FLOOR_ENTRIES = 200, ARG_FLOOR_LEAVES = 300,
       ARG_GRACE_MS = 2000 };

const char arg_gen_src[] = "tools/gen_api_reference.c";
const char arg_template[] = "docs/API_REFERENCE.md.in";
const char arg_doc[] = "build/gen/API_REFERENCE.md"; // error-doc-ref-ok:written by make docs-api-reference
/* The POSIX default scratch parent when TMPDIR is unset. */
const char arg_tmp_default[] = { '/', 't', 'm', 'p', '\0' };

static const char arg_name[] = "check_api_reference_generated";
static const char arg_def_pattern[] =
    "^[[:space:]]*#include[[:space:]]+\"\\.\\./"
    "(engine/composition/commands/[A-Za-z0-9_/]+\\.def)\"";

static int arg_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

static int arg_add_def(struct arg_defs *d, const char *line, const regmatch_t *m)
{
    size_t len = (size_t)(m->rm_eo - m->rm_so);
    if (len >= ARG_DEF_PATH || d->n >= ARG_DEF_MAX)
        return die("check_api_reference_generated: too many or too long .def paths: %s\n", line);
    memcpy(d->path[d->n], line + m->rm_so, len);
    d->path[d->n][len] = '\0';
    d->n++;
    return 0;
}

static void arg_dedupe(struct arg_defs *d)
{
    size_t w = 0;
    qsort(d->path, d->n, sizeof d->path[0], arg_cmp);
    for (size_t r = 0; r < d->n; r++)
        if (w == 0 || strcmp(d->path[w - 1], d->path[r]) != 0) {
            if (w != r)
                memcpy(d->path[w], d->path[r], sizeof d->path[0]);
            w++;
        }
    d->n = w;
}

int arg_def_list(struct arg_defs *d)
{
    regex_t re;
    regmatch_t m[2];
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    d->n = 0;
    FILE *f = fopen(arg_gen_src, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", arg_gen_src);
    if (regcomp(&re, arg_def_pattern, REG_EXTENDED) != 0) {
        fclose(f);
        return die("z23-lint: bad pattern %s\n", arg_def_pattern);
    }
    while (rc == 0 && getline(&line, &cap, f) >= 0)
        if (regexec(&re, line, 2, m, 0) == 0)
            rc = arg_add_def(d, line, &m[1]);
    regfree(&re);
    rc = fin(f, line, arg_gen_src, rc);
    arg_dedupe(d);
    return rc;
}

static int arg_preflight(const struct arg_io *io, struct arg_defs *d)
{
    const char *const req[] = { arg_gen_src, arg_template };
    for (size_t i = 0; i < sizeof req / sizeof req[0]; i++)
        if (access(req[i], F_OK) != 0) {
            fprintf(io->err, "%s: FATAL — missing %s\n", arg_name, req[i]);
            return 2;
        }
    if (arg_def_list(d) != 0)
        return 2;
    int missing = 0;
    for (size_t i = 0; i < d->n; i++)
        if (access(d->path[i], F_OK) != 0) {
            fprintf(io->err, "%s: FATAL — %s includes %s, which does not exist\n",
                    arg_name, arg_gen_src, d->path[i]);
            missing = 1;
        }
    if (missing)
        return 2;
    return gate_require_scanned((int)d->n, ARG_FLOOR_DEFS, arg_name,
                                "no .def catalogs included by "
                                "tools/gen_api_reference.c — the command catalog moved?");
}

/* Writes the buffer's lines, each prefixed by four spaces; limit 0 is no cap. */
void arg_indent(FILE *out, const char *data, size_t limit)
{
    size_t lines = 0;
    while (data && *data && (limit == 0 || lines < limit)) {
        const char *nl = strchr(data, '\n');
        size_t n = nl ? (size_t)(nl - data) : strlen(data);
        fprintf(out, "    %.*s\n", (int)n, data);
        data += n + (nl ? 1 : 0);
        lines++;
    }
}

/* Runs argv; 0 with *code set, 1 when a signal ended the run, 2 when it
 * could not start. */
static int arg_exec(char *const *argv, enum lcp_mode mode, struct lcp_buf *out,
                    int *code)
{
    struct lcp_spec s = { .argv = argv, .mode = mode, .grace_ms = ARG_GRACE_MS };
    int rc = lcp_run(&s, out, code);
    return rc < 0 ? 2 : rc;
}

int arg_open_scratch(struct arg_scratch *s)
{
    const char *tmp = env_or("TMPDIR", arg_tmp_default);
    int n = snprintf(s->dir, sizeof s->dir, "%s/zcl-apiref.XXXXXX", tmp);
    if (n < 0 || (size_t)n >= sizeof s->dir || !mkdtemp(s->dir)) {
        s->dir[0] = '\0';
        return -1;
    }
    snprintf(s->bin, sizeof s->bin, "%s/gen_api_reference", s->dir);
    snprintf(s->expected, sizeof s->expected, "%s", arg_doc);
    return 0;
}

static int arg_build(const struct arg_io *io, const struct arg_scratch *s)
{
    char *const argv[] = { (char *)env_or("CC", "cc"), (char *)"-std=c23", (char *)"-O0",
        (char *)"-Wall", (char *)"-Wextra", (char *)"-Werror",
        (char *)"-Iengine/modules/kernel/include", (char *)"-Iplatform/modules/json/include",
        (char *)"-Iplatform/modules/base/include", (char *)"-o", (char *)s->bin,
        (char *)arg_gen_src, NULL };
    struct lcp_buf log = { 0 };
    int code = 0, rc = arg_exec(argv, LCP_ERR, &log, &code);
    if (rc == 0 && code != 0)
        rc = 2;
    if (rc == 2) {
        fprintf(io->err, "%s: FATAL — %s does not compile:\n", arg_name, arg_gen_src);
        arg_indent(io->err, log.data, 0);
    }
    lcp_buf_free(&log);
    return rc;
}

/* Length of the digits when the line is `gen_api_reference: N catalog entries...`, else 0. */
static size_t arg_entry_digits(const char *line)
{
    static const char head[] = "gen_api_reference: ";
    static const char tail[] = " catalog entries";
    if (strncmp(line, head, sizeof head - 1) != 0)
        return 0;
    const char *d = line + sizeof head - 1;
    size_t n = strspn(d, "0123456789");
    return strncmp(d + n, tail, sizeof tail - 1) == 0 ? n : 0;
}

/* The first matching line's number as digits, empty when none matches. */
static void arg_entries(const char *log, char *digits, size_t cap)
{
    digits[0] = '\0';
    while (*log) {
        size_t n = arg_entry_digits(log);
        if (n > 0 && n < cap) {
            memcpy(digits, log + strlen("gen_api_reference: "), n);
            digits[n] = '\0';
            return;
        }
        const char *nl = strchr(log, '\n');
        log = nl ? nl + 1 : log + strlen(log);
    }
}

static int arg_entry_floor(const char *digits)
{
    long long v = digits[0] ? strtoll(digits, NULL, 10) : 0;
    return v > INT_MAX ? INT_MAX : (int)v;
}

static int arg_generate(const struct arg_io *io, struct arg_scratch *s)
{
    char *const argv[] = { s->bin, (char *)arg_template, s->expected, NULL };
    if (csr_mkdirs("build/gen") != 0)
        return die("z23-lint: cannot create build/gen\n", "");
    struct lcp_buf log = { 0 };
    int code = 0, rc = arg_exec(argv, LCP_ERR, &log, &code);
    if (rc == 0 && code != 0)
        rc = 2;
    if (rc == 2) {
        fprintf(io->err, "%s: FATAL — the generator failed:\n", arg_name);
        arg_indent(io->err, log.data, 0);
    } else if (rc == 0) {
        arg_entries(log.data ? log.data : "", s->entries, sizeof s->entries);
        rc = gate_require_scanned(arg_entry_floor(s->entries), ARG_FLOOR_ENTRIES, arg_name,
                                  "the generator emitted almost no catalog entries — "
                                  "the X-macro expansion broke");
    }
    lcp_buf_free(&log);
    return rc;
}

/* The whole file as one NUL-terminated heap buffer, or NULL. */
char *arg_slurp(const char *path)
{
    FILE *f = fopen(path, "rb");
    char *buf = NULL;
    long size = 0;
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) == 0 && (size = ftell(f)) >= 0 && fseek(f, 0, SEEK_SET) == 0
        && (buf = malloc((size_t)size + 1)) != NULL) { // raw-alloc-ok:lint-runtime
        size_t got = fread(buf, 1, (size_t)size, f);
        if (got != (size_t)size || ferror(f)) {
            free(buf);
            buf = NULL;
        } else {
            buf[size] = '\0';
        }
    }
    fclose(f);
    return buf;
}

/* True when `line` occurs in text as a whole line. */
static int arg_has_line(const char *text, const char *line, size_t len)
{
    for (const char *p = text; (p = strstr(p, line)) != NULL; p += len) {
        int starts = p == text || p[-1] == '\n';
        int ends = p[len] == '\n' || p[len] == '\0';
        if (starts && ends)
            return 1;
    }
    return 0;
}

/* Every heading of the editorial template must survive into the output. */
static int arg_check_sections(const struct arg_io *io, const char *tpl, const char *out)
{
    int missing = 0;
    for (const char *p = tpl; *p;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char head[256];
        if (n > 0 && p[0] == '#' && n < sizeof head) {
            memcpy(head, p, n);
            head[n] = '\0';
            if (!arg_has_line(out, head, n)) {
                fprintf(io->err, "%s: required section missing from %s: %s\n", arg_name,
                        arg_doc, head);
                missing++;
            }
        }
        p += n + (nl ? 1 : 0);
    }
    if (strncmp(out, "<!-- ZCL-GEN:", 13) == 0 || strstr(out, "\n<!-- ZCL-GEN:") != NULL) {
        fprintf(io->err, "%s: %s still holds an unexpanded ZCL-GEN marker\n", arg_name, arg_doc);
        missing++;
    }
    return missing;
}

/* Parses `ZCL_COMMAND_<KIND>("<path>"` with s just past `ZCL_COMMAND_`; 1 and the
 * path for a leaf, 0 for a branch or anything else (branches own no row). */
static int arg_leaf_at(const char *s, char *path, size_t cap)
{
    size_t n = strspn(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_");
    const char *q = s + n;
    if (n == 0 || (n == 6 && strncmp(s, "BRANCH", 6) == 0))
        return 0;
    q += strspn(q, " \t\r\n");
    if (*q != '(')
        return 0;
    q += 1 + strspn(q + 1, " \t\r\n");
    if (*q != '"')
        return 0;
    q++;
    size_t len = strcspn(q, "\"");
    if (len == 0 || len >= cap)
        return 0;
    for (size_t i = 0; i < len; i++)
        path[i] = q[i] == '.' ? ' ' : q[i];
    path[len] = '\0';
    return 1;
}

/* Counts the leaves of one .def and reports each whose CLI row is absent. */
static int arg_check_def(const struct arg_io *io, const char *def, const char *out, size_t *leaves)
{
    char *text = arg_slurp(def);
    int missing = 0;
    if (!text)
        return -1;
    for (const char *p = text; (p = strstr(p, "ZCL_COMMAND_")) != NULL; p += 12) {
        char path[160], needle[170];
        if (!arg_leaf_at(p + 12, path, sizeof path))
            continue;
        (*leaves)++;
        snprintf(needle, sizeof needle, "`%s`", path);
        if (strstr(out, needle) == NULL) {
            fprintf(io->err, "%s: command leaf `%s` (%s) is missing from %s\n", arg_name, path,
                    def, arg_doc);
            missing++;
        }
    }
    free(text);
    return missing;
}

/* Verifies the generated reference against the sources it came from: every
 * template heading is present and every command leaf of the .def catalogs has
 * a row. 0 clean, 1 a check failed, 2 fatal. */
int arg_verify(const struct arg_io *io, const struct arg_defs *d, char *entries, size_t cap)
{
    char *out = arg_slurp(arg_doc), *tpl = arg_slurp(arg_template);
    size_t leaves = 0;
    int bad = 0, rc = 0;
    if (!out || !tpl) {
        fprintf(io->err, "%s: FATAL — cannot read %s\n", arg_name, out ? arg_template : arg_doc);
        rc = 2;
    } else {
        bad = arg_check_sections(io, tpl, out);
        for (size_t i = 0; rc == 0 && i < d->n; i++) {
            int m = arg_check_def(io, d->path[i], out, &leaves);
            rc = m < 0 ? 2 : 0;
            bad += m > 0 ? m : 0;
        }
        if (rc == 0 && gate_require_scanned((int)leaves, ARG_FLOOR_LEAVES, arg_name,
                                            "almost no command leaves found in the .def catalogs"))
            rc = 2;
    }
    free(out);
    free(tpl);
    if (rc == 0 && bad == 0)
        snprintf(entries, cap, "%zu", leaves);
    return rc ? rc : bad > 0;
}

static int arg_steps(const struct arg_io *io, struct arg_scratch *s, const struct arg_defs *defs)
{
    char leaves[24];
    int rc = arg_build(io, s);
    if (rc == 0 && lsc_pending() == 0)
        rc = arg_generate(io, s);
    if (rc != 0 || lsc_pending())
        return rc ? rc : 1;
    rc = arg_verify(io, defs, leaves, sizeof leaves);
    if (rc == 1)
        fprintf(io->err, "FAIL: %s is generated into build/gen and is incomplete.\n"
                "  Fix the catalog (engine/composition/commands/*.def) or the editorial template\n"
                "  (%s), or the generator (%s); regenerate with: make docs-api-reference\n",
                arg_doc, arg_template, arg_gen_src);
    if (rc == 0)
        fprintf(io->out, "%s: clean — %s carries every template section and all %s command leaves "
                "of %zu .def catalog(s) / %s entries\n", arg_name, arg_doc, leaves, defs->n,
                s->entries);
    return rc;
}

int arg_gate(const struct arg_io *io)
{
    struct arg_defs defs;
    struct arg_scratch s = { .dir = "" };
    int rc = arg_preflight(io, &defs), owned = 0;
    if (rc == 0 && arg_open_scratch(&s) != 0) {
        fprintf(io->err, "z23-lint: cannot create a scratch directory under %s\n",
                env_or("TMPDIR", arg_tmp_default));
        rc = 2;
    } else if (rc == 0) {
        owned = 1;
        rc = arg_steps(io, &s, &defs);
    }
    if (owned)
        (void)rap_rm_rf(s.dir);
    return rc;
}

int check_api_reference_generated_run(int argc, char **argv)
{
    struct arg_io io = { stdout, stderr };
    (void)argc;
    (void)argv;
    if (lsc_install() != 0)
        return die("z23-lint: cannot install signal handlers\n", "");
    int rc = arg_gate(&io);
    fflush(stdout);
    int sig = lsc_pending();
    if (sig)
        lsc_finish(sig);
    return rc;
}
