/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: registry parsing and document generation of check-cookbook. The
 * record rules are those of the awk program in the replaced
 * check_cookbook.sh: a record starts on a line beginning KIND( and ends on a
 * line whose last non-blank character is ), its double-quoted fields are
 * taken in order, and a Z23_DEV token between commas marks the tool.
 */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "gate_cookbook_priv.h"

int ck_cat(struct ck_str *s, const char *text)
{
    size_t n = strlen(text);
    if (s->n + n + 1 > s->cap) {
        size_t cap = s->cap * 2 > s->n + n + 1 ? s->cap * 2 : s->n + n + 1;
        char *p = realloc(s->p, cap < 256 ? 256 : cap); // raw-alloc-ok:lint-runtime
        if (!p)
            return -1;
        s->p = p;
        s->cap = cap < 256 ? 256 : cap;
    }
    memcpy(s->p + s->n, text, n + 1);
    s->n += n;
    return 0;
}

void ck_str_free(struct ck_str *s)
{
    free(s->p);
    *s = (struct ck_str){ 0 };
}

void ck_recs_free(struct ck_recs *r)
{
    for (size_t i = 0; i < r->n; i++)
        free(r->line[i]);
    free(r->line);
    *r = (struct ck_recs){ 0 };
}

static const char *const k_ck_kinds[] = { "SECTION(", "RECIPE_RUN(", "RECIPE_ASK(", "RECIPE_READ(" };

static int ck_starts_record(const char *line)
{
    for (size_t i = 0; i < sizeof k_ck_kinds / sizeof k_ck_kinds[0]; i++) {
        if (strncmp(line, k_ck_kinds[i], strlen(k_ck_kinds[i])) == 0)
            return 1;
    }
    return 0;
}

static int ck_ends_record(const char *line)
{
    size_t n = strlen(line);
    while (n && isspace((unsigned char)line[n - 1]))
        n--;
    return n && line[n - 1] == ')';
}

/* Length of the double-quoted string starting at s[0], or 0 when none. */
static size_t ck_quoted_len(const char *s)
{
    size_t i = 1;
    while (s[i] && s[i] != '"') {
        if (s[i] == '\\') {
            if (!s[i + 1])
                return 0;
            i++;
        }
        i++;
    }
    return s[i] == '"' ? i + 1 : 0;
}

/* The regex ,[[:space:]]*Z23_DEV[[:space:]]*, anywhere in s. */
static int ck_has_tool(const char *s)
{
    for (const char *c = strchr(s, ','); c; c = strchr(c + 1, ',')) {
        const char *p = c + 1;
        while (isspace((unsigned char)*p))
            p++;
        if (strncmp(p, "Z23_DEV", 7) != 0)
            continue;
        p += 7;
        while (isspace((unsigned char)*p))
            p++;
        if (*p == ',')
            return 1;
    }
    return 0;
}

static int ck_push(struct ck_recs *r, char *line)
{
    if (r->n == r->cap) {
        size_t cap = r->cap ? r->cap * 2 : 64;
        char **p = realloc(r->line, cap * sizeof *p); // raw-alloc-ok:lint-runtime
        if (!p)
            return -1;
        r->line = p;
        r->cap = cap;
    }
    r->line[r->n++] = line;
    return 0;
}

static int ck_emit_parts(struct ck_str *s, const char *buf)
{
    for (const char *p = buf; *p; p++) {
        size_t n = *p == '"' ? ck_quoted_len(p) : 0;
        if (!n)
            continue;
        char *part = strndup(p + 1, n - 2);
        int bad = !part || ck_cat(s, "\t") != 0 || ck_cat(s, part) != 0;
        free(part);
        if (bad)
            return -1;
        p += n - 1;
    }
    return 0;
}

static int ck_emit(struct ck_recs *r, const char *kind, size_t kind_len, const char *buf)
{
    struct ck_str s = { 0 };
    char *k = strndup(kind, kind_len);
    int bad = !k || ck_cat(&s, k) != 0 || ck_emit_parts(&s, buf) != 0;
    free(k);
    if (!bad && ck_has_tool(buf))
        bad = ck_cat(&s, "\tZ23_DEV") != 0;
    if (!bad && ck_push(r, s.p) != 0)
        bad = 1;
    if (bad)
        ck_str_free(&s);
    return bad ? -1 : 0;
}

int ck_parse(const char *text, struct ck_recs *r)
{
    struct ck_str buf = { 0 };
    const char *kind = NULL;
    size_t kind_len = 0;
    int collecting = 0, rc = 0;
    *r = (struct ck_recs){ 0 };
    for (const char *p = text; *p && rc == 0;) {
        size_t n = strcspn(p, "\n");
        char *line = strndup(p, n);
        if (!line) {
            rc = -1;
            break;
        }
        if (ck_starts_record(line)) {
            collecting = 1;
            buf.n = 0;
            kind = strchr(line, '(') ? p : NULL;
            kind_len = (size_t)(strchr(line, '(') - line);
        }
        if (collecting)
            rc = ck_cat(&buf, " ") || ck_cat(&buf, line);
        if (collecting && rc == 0 && ck_ends_record(line)) {
            collecting = 0;
            rc = ck_emit(r, kind, kind_len, buf.p);
        }
        free(line);
        p += n + (p[n] == '\n');
    }
    ck_str_free(&buf);
    if (rc)
        ck_recs_free(r);
    return rc;
}

void ck_split(char *line, char *f[CK_FIELDS])
{
    char *p = line;
    for (int i = 0; i < CK_FIELDS; i++)
        f[i] = line + strlen(line);
    while (*p == '\t')
        p++;
    for (int i = 0; i < CK_FIELDS - 1 && *p; i++) {
        f[i] = p;
        p += strcspn(p, "\t");
        if (*p)
            *p++ = '\0';
        while (*p == '\t')
            p++;
    }
    if (*p) {
        f[CK_FIELDS - 1] = p;
        size_t n = strlen(p);
        while (n && p[n - 1] == '\t')
            p[--n] = '\0';
    }
}

int ck_args_safe(const char *s)
{
    if (!*s)
        return 0;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                 || c == '_' || c == '.' || c == '/' || c == '=' || c == ' ' || c == '-';
        if (!ok)
            return 0;
    }
    return 1;
}

static const char k_ck_head[] =
    "# Z23 cookbook\n\n"
    "<!-- GENERATED FROM engine/composition/cookbook.def BY tools/lint/check_cookbook.sh --fix.\n"
    "     DO NOT EDIT THIS FILE. Edit the registry and regenerate. -->\n\n"
    "One question, one answer. This is the lookup table, not the workflow:\n"
    "`docs/dev/DEVELOPING.md` is the ORDER you do things in, and you read it once.\n"
    "Come back here every time you forget the exact incantation.\n\n"
    "Every recipe below is checked by `make check-cookbook`. A RUN recipe has\n"
    "its command executed and its expected token required in the output. An ASK\n"
    "recipe is one whose command is too slow to run in a lint gate, so only its\n"
    "existence and readiness are checked. A READ recipe cites code that must\n"
    "still be tracked and must still contain the symbol named.\n";

static int ck_cats(struct ck_str *o, const char *const *parts)
{
    for (; *parts; parts++) {
        if (ck_cat(o, *parts) != 0)
            return -1;
    }
    return 0;
}

static int ck_doc_row(struct ck_str *o, char *const *f)
{
    const char *kind = f[0];
    if (strcmp(kind, "SECTION") == 0)
        return ck_cats(o, (const char *const[]){ "\n## ", f[1], "\n", NULL });
    if (ck_cats(o, (const char *const[]){ "\n### ", f[2], "\n\n", NULL }) != 0)
        return -1;
    if (strcmp(kind, "RECIPE_RUN") == 0)
        return ck_cats(o, (const char *const[]){ "    z23 ", f[3], "\n\nLook for `", f[4],
                                                 "` in the output. (`", f[1], "`, RUN)\n", NULL });
    if (strcmp(kind, "RECIPE_ASK") == 0) {
        char *dotted = strdup(f[3]);
        if (!dotted)
            return -1;
        for (char *d = dotted; *d; d++)
            *d = *d == '.' ? ' ' : *d;
        int rc = ck_cats(o, (const char *const[]){ "    z23 ", dotted,
                                                   "\n\nSlower than the rest, so the gate checks only that it is `",
                                                   f[4], "`. (`", f[1], "`, ASK)\n", NULL });
        free(dotted);
        return rc;
    }
    if (strcmp(kind, "RECIPE_READ") == 0)
        return ck_cats(o, (const char *const[]){ "Worked example: `", f[3], "`, look for `", f[4],
                                                 "`. (`", f[1], "`, READ)\n", NULL });
    return 0;
}

int ck_doc(const struct ck_recs *r, struct ck_str *out)
{
    *out = (struct ck_str){ 0 };
    if (ck_cat(out, k_ck_head) != 0)
        return -1;
    for (size_t i = 0; i < r->n; i++) {
        char *copy = strdup(r->line[i]);
        char *f[CK_FIELDS];
        if (!copy)
            return -1;
        ck_split(copy, f);
        int rc = ck_doc_row(out, f);
        free(copy);
        if (rc != 0)
            return -1;
    }
    return 0;
}
