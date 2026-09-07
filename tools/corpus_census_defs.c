/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * corpus-census: scopes.def line grammar and file loading (slice 1b). Reads
 * contexts/commons/corpus/scopes.def, parses each repo-scope line
 * (`scope|kind|spdx|src[,tests]`) and package-scope line
 * (`package|root|store|kind|spdx`), and hashes the raw file bytes into
 * def_sha3 for the evidence bundle. See tools/corpus_census.c for the full
 * driver overview and the evidence-root recipes each field feeds.
 */

#define _GNU_SOURCE

#include "corpus_census_priv.h"

#include "base/checked.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"
#include "vcs/zcode_c23_corpus.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static bool prefix_list_parse(struct prefix *out, size_t *count,
                              const char *list, size_t line_no)
{
    size_t n = 0;
    const char *p = list;
    for (;;) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        if (!len || n == CORPUS_CENSUS_MAX_PREFIXES) {
            LOG_ERROR(CENSUS_LOG, "line %zu: bad prefix list '%s'",
                      line_no, list);
            return false;
        }
        char *copy = zcl_malloc(len + 1u, "corpus.prefix");
        if (!copy)
            LOG_FAIL(CENSUS_LOG, "prefix alloc %zu (line %zu)", len,
                     line_no);
        memcpy(copy, p, len);
        copy[len] = '\0';
        if (!shell_safe(copy)) {
            LOG_ERROR(CENSUS_LOG, "line %zu: bad prefix '%s'", line_no,
                      copy);
            free(copy);
            return false;
        }
        out[n].text = copy;
        out[n].is_dir = copy[len - 1] == '/';
        n++;
        if (!comma) break;
        p = comma + 1;
    }
    *count = n;
    return true;
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    size_t len = strlen(s);
    while (len && isspace((unsigned char)s[len - 1])) s[--len] = '\0';
    return s;
}

static bool key_value(const char *token, const char *key,
                      const char **value)
{
    size_t klen = strlen(key);
    if (strncmp(token, key, klen) != 0 || token[klen] != ' ') return false;
    token += klen + 1;
    while (isspace((unsigned char)*token)) token++;
    if (!*token) return false;
    *value = token;
    return true;
}

static bool kind_parse(const char *value, uint16_t *kind_out)
{
    if (strcmp(value, "human") == 0)
        *kind_out = VCS_ZCODE_SOURCE_HUMAN_AUTHORED;
    else if (strcmp(value, "ai") == 0)
        *kind_out = VCS_ZCODE_SOURCE_AI_AUTHORED;
    else if (strcmp(value, "import") == 0)
        *kind_out = VCS_ZCODE_SOURCE_CANONICAL_IMPORT;
    else
        return false;
    return true;
}

/* store_label_valid — the `store` field of a package def line is a LABEL,
 * not a path: one path component drawn from [A-Za-z0-9._-], never '.' or
 * '..', never containing '/' or '~'.
 *
 * WHY A LABEL AND NOT A PATH. The census copies the def line verbatim into
 * every evidence record (`scopes_def_line`) and hashes it into
 * assignment_evidence_root, and emits the store field again as `"store"` in
 * both the evidence and the KPI report. When that field held an absolute
 * datadir, 2,302 copies of the operator's home directory shipped in the
 * committed corpus artifacts — a clearnet locator in a repository whose
 * privacy rule is that committed files carry no local filesystem paths,
 * usernames, or hostnames. The path was never what the evidence was ABOUT:
 * every root is computed over content hashes, and the def `root` (the
 * package manifest root, re-derived from the store and refused on mismatch)
 * is what actually binds the bytes. The store field only says WHICH local
 * store to read, so it is now a stable name that means the same thing on
 * every host, resolved through --store-root / $ZCL_CORPUS_STORE_ROOT / $HOME
 * at run time. */
static bool store_label_valid(const char *s)
{
    if (!s || !*s) return false;
    if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0) return false;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '.' || c == '_' || c == '-'))
            return false;
    }
    return true;
}

/* ── package line field validators ────────────────────────────────── */

static bool def_field_package_name(struct scope_def *def, const char *value,
                                   size_t line_no)
{
    if (!shell_safe(value) ||
        !(def->name = dup_str(value, "corpus.scopename"))) {
        LOG_ERROR(CENSUS_LOG, "line %zu: bad package name", line_no);
        return false;
    }
    return true;
}

static bool def_field_package_root(struct scope_def *def, const char *value,
                                   size_t line_no)
{
    if (strlen(value) != 64 ||
        !zcl_hex_decode_lower(value, def->package_root, 32) ||
        !zcl_bytes_any_set(def->package_root, 32)) {
        LOG_ERROR(CENSUS_LOG,
                  "line %zu: bad package root (want 64 lowercase "
                  "hex, nonzero)", line_no);
        return false;
    }
    return true;
}

static bool def_field_package_store(struct scope_def *def, const char *value,
                                    size_t line_no)
{
    if (!store_label_valid(value) ||
        !(def->store = dup_str(value, "corpus.store"))) {
        LOG_ERROR(CENSUS_LOG,
                  "line %zu: store must be a LABEL — one path "
                  "component, [A-Za-z0-9._-], not '.' or '..' — "
                  "not a path (got '%s'). The label resolves to "
                  "<store-root>/<label> at run time; an absolute "
                  "path here would publish the operator's home "
                  "directory in every committed census artifact",
                  line_no, value ? value : "");
        return false;
    }
    return true;
}

static bool def_field_package_kind(struct scope_def *def, const char *value,
                                   size_t line_no)
{
    if (!kind_parse(value, &def->kind)) {
        LOG_ERROR(CENSUS_LOG, "line %zu: bad kind '%s'", line_no, value);
        return false;
    }
    return true;
}

static bool def_field_package_spdx(struct scope_def *def, const char *value,
                                   size_t line_no)
{
    if (!shell_safe(value) ||
        !(def->spdx = dup_str(value, "corpus.spdx"))) {
        LOG_ERROR(CENSUS_LOG, "line %zu: bad spdx", line_no);
        return false;
    }
    return true;
}

/* Dispatch one `|`-separated token of a package line to its field
 * validator; `field` counts tokens seen so far (0-based). A token that
 * does not match the expected key at this position is the fatal
 * out-of-order/unknown-field case. */
static bool def_parse_package_field(struct scope_def *def, size_t field,
                                    char *t, size_t line_no)
{
    const char *value = NULL;
    switch (field) {
    case 0:
        if (key_value(t, "package", &value))
            return def_field_package_name(def, value, line_no);
        break;
    case 1:
        if (key_value(t, "root", &value))
            return def_field_package_root(def, value, line_no);
        break;
    case 2:
        if (key_value(t, "store", &value))
            return def_field_package_store(def, value, line_no);
        break;
    case 3:
        if (key_value(t, "kind", &value))
            return def_field_package_kind(def, value, line_no);
        break;
    case 4:
        if (key_value(t, "spdx", &value))
            return def_field_package_spdx(def, value, line_no);
        break;
    default:
        break;
    }
    LOG_ERROR(CENSUS_LOG,
              "line %zu: expected package|root|store|kind|spdx "
              "field order, got '%s'", line_no, t);
    return false;
}

/* The package line form:
 *   package <name> | root <64hex> | store <label> | kind <k> | spdx <id>
 */
static bool def_parse_package_line(struct scope_def *def, const char *line,
                                   size_t line_no)
{
    memset(def, 0, sizeof(*def));
    def->is_package = true;
    def->def_line = dup_str(line, "corpus.defline");
    char *work = dup_str(line, "corpus.defwork");
    if (!def->def_line || !work) {
        free(work);
        return false;
    }
    bool ok = false;
    size_t field = 0;
    for (char *tok = strtok(work, "|"); tok; tok = strtok(NULL, "|")) {
        char *t = trim(tok);
        if (!def_parse_package_field(def, field, t, line_no)) goto done;
        field++;
    }
    if (!def->name || !zcl_bytes_any_set(def->package_root, 32) || !def->store ||
        !def->kind || !def->spdx) {
        LOG_ERROR(CENSUS_LOG,
                  "line %zu: package scope needs package, root, store, "
                  "kind and spdx", line_no);
        goto done;
    }
    ok = true;
done:
    free(work);
    if (!ok) scope_def_free(def);
    return ok;
}

/* ── repo scope line field validators ─────────────────────────────── */

static bool def_field_scope_name(struct scope_def *def, const char *value,
                                 size_t line_no)
{
    if (!shell_safe(value) || !(def->name = dup_str(value, "corpus.scopename"))) {
        LOG_ERROR(CENSUS_LOG, "line %zu: bad scope name", line_no);
        return false;
    }
    return true;
}

static bool def_field_scope_kind(struct scope_def *def, const char *value,
                                 size_t line_no)
{
    if (strcmp(value, "human") == 0)
        def->kind = VCS_ZCODE_SOURCE_HUMAN_AUTHORED;
    else if (strcmp(value, "ai") == 0)
        def->kind = VCS_ZCODE_SOURCE_AI_AUTHORED;
    else if (strcmp(value, "import") == 0)
        def->kind = VCS_ZCODE_SOURCE_CANONICAL_IMPORT;
    else {
        LOG_ERROR(CENSUS_LOG, "line %zu: bad kind '%s'", line_no, value);
        return false;
    }
    return true;
}

static bool def_field_scope_spdx(struct scope_def *def, const char *value,
                                 size_t line_no)
{
    if (!shell_safe(value) ||
        !(def->spdx = dup_str(value, "corpus.spdx"))) {
        LOG_ERROR(CENSUS_LOG, "line %zu: bad spdx", line_no);
        return false;
    }
    return true;
}

static bool def_field_scope_src(struct scope_def *def, const char *value,
                                size_t line_no)
{
    return prefix_list_parse(def->src, &def->nsrc, value, line_no);
}

static bool def_field_scope_tests(struct scope_def *def, const char *value,
                                  size_t line_no)
{
    return prefix_list_parse(def->tests, &def->ntests, value, line_no);
}

/* Dispatch one `|`-separated token of a repo scope line. `src` is expected
 * at field 3; `tests` may follow it OR, when `src` is absent, appear at
 * field 3 itself — the same precedence the original grammar checked
 * (src wins the field-3 slot when both would match, which they cannot:
 * key_value requires the literal keyword). */
static bool def_parse_scope_field(struct scope_def *def, size_t field,
                                  char *t, size_t line_no, bool *seen_tests)
{
    const char *value = NULL;
    if (field == 0 && key_value(t, "scope", &value))
        return def_field_scope_name(def, value, line_no);
    if (field == 1 && key_value(t, "kind", &value))
        return def_field_scope_kind(def, value, line_no);
    if (field == 2 && key_value(t, "spdx", &value))
        return def_field_scope_spdx(def, value, line_no);
    if (field == 3 && key_value(t, "src", &value))
        return def_field_scope_src(def, value, line_no);
    if (field >= 3 && !*seen_tests && key_value(t, "tests", &value)) {
        if (!def_field_scope_tests(def, value, line_no)) return false;
        *seen_tests = true;
        return true;
    }
    LOG_ERROR(CENSUS_LOG,
              "line %zu: expected scope|kind|spdx|src[,tests] "
              "field order, got '%s'", line_no, t);
    return false;
}

static bool def_parse_line(struct scope_def *def, const char *line,
                           size_t line_no)
{
    memset(def, 0, sizeof(*def));
    if (strncmp(line, "package ", 8) == 0)
        return def_parse_package_line(def, line, line_no);
    def->def_line = dup_str(line, "corpus.defline");
    char *work = dup_str(line, "corpus.defwork");
    if (!def->def_line || !work) {
        free(work);
        return false;
    }

    bool ok = false;
    bool seen_tests = false;
    size_t field = 0;
    for (char *tok = strtok(work, "|"); tok; tok = strtok(NULL, "|")) {
        char *t = trim(tok);
        if (!def_parse_scope_field(def, field, t, line_no, &seen_tests))
            goto done;
        field++;
    }
    if (!def->name || !def->kind || !def->spdx ||
        (!def->nsrc && !def->ntests)) {
        LOG_ERROR(CENSUS_LOG,
                  "line %zu: scope needs scope, kind, spdx and at least "
                  "one of src/tests", line_no);
        goto done;
    }
    ok = true;
done:
    free(work);
    if (!ok) scope_def_free(def);
    return ok;
}

static int cmp_scope_def(const void *a, const void *b)
{
    return strcmp(((const struct scope_def *)a)->name,
                  ((const struct scope_def *)b)->name);
}

void scope_def_free(struct scope_def *def)
{
    if (!def) return;
    free(def->name);
    free(def->spdx);
    free(def->def_line);
    free(def->store);
    for (size_t i = 0; i < def->nsrc; i++) free(def->src[i].text);
    for (size_t i = 0; i < def->ntests; i++) free(def->tests[i].text);
    memset(def, 0, sizeof(*def));
}

/* Read every line of the def file, skip blank/comment lines, and hash the
 * RAW bytes (including skipped lines) into def_sha3 as they are read. */
static bool def_load_read_lines(FILE *f, const char *path,
                                struct str_vec *lines, uint8_t def_sha3[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    char *line = NULL;
    size_t cap = 0, total = 0;
    ssize_t got;
    bool ok = false;
    while ((got = getline(&line, &cap, f)) >= 0) {
        total += (size_t)got;
        if (total > CORPUS_CENSUS_DEF_MAX_BYTES) {
            LOG_ERROR(CENSUS_LOG, "def %s over %u bytes", path,
                      CORPUS_CENSUS_DEF_MAX_BYTES);
            goto done;
        }
        sha3_256_write(&sha, (const uint8_t *)line, (size_t)got);
        while (got && (line[got - 1] == '\n' || line[got - 1] == '\r'))
            line[--got] = '\0';
        char *t = trim(line);
        if (!*t || *t == '#') continue;
        if (!vec_push(lines, t)) goto done;
    }
    sha3_256_finalize(&sha, def_sha3);
    if (ferror(f)) {
        LOG_ERROR(CENSUS_LOG, "read def %s: %s", path, strerror(errno));
        goto done;
    }
    ok = true;
done:
    free(line);
    return ok;
}

static bool def_load_parse_all(struct scope_def *defs,
                               const struct str_vec *lines)
{
    for (size_t i = 0; i < lines->n; i++) {
        if (!def_parse_line(&defs[i], lines->v[i], i + 1u))
            return false;
    }
    return true;
}

static bool def_load_check_duplicates(const struct scope_def *defs,
                                      size_t count)
{
    for (size_t i = 1; i < count; i++) {
        if (strcmp(defs[i - 1].name, defs[i].name) == 0) {
            LOG_ERROR(CENSUS_LOG, "duplicate scope name %s", defs[i].name);
            return false;
        }
    }
    return true;
}

bool def_load(const char *path, struct scope_def **defs_out,
             size_t *count_out, uint8_t def_sha3[32])
{
    FILE *f = fopen(path, "rb");
    if (!f)
        LOG_FAIL(CENSUS_LOG, "open def %s: %s", path, strerror(errno));
    struct str_vec lines = {0};
    bool ok = false;
    struct scope_def *defs = NULL;
    if (!def_load_read_lines(f, path, &lines, def_sha3)) goto done;
    if (!lines.n) {
        LOG_ERROR(CENSUS_LOG, "def %s defines no scopes", path);
        goto done;
    }
    defs = zcl_calloc(lines.n, sizeof(*defs), "corpus.defs");
    if (!defs) {
        LOG_ERROR(CENSUS_LOG, "defs alloc %zu", lines.n);
        goto done;
    }
    if (!def_load_parse_all(defs, &lines)) goto done;
    qsort(defs, lines.n, sizeof(*defs), cmp_scope_def);
    if (!def_load_check_duplicates(defs, lines.n)) goto done;
    *defs_out = defs;
    *count_out = lines.n;
    defs = NULL;
    ok = true;
done:
    if (defs) {
        for (size_t i = 0; i < lines.n; i++) scope_def_free(&defs[i]);
        free(defs);
    }
    vec_free(&lines);
    fclose(f);
    return ok;
}
