/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: recognize exact native SQLite column declarations for migration replay. */
#ifndef ZCL_DATABASE_SCHEMA_COLUMN_INTERNAL_H
#define ZCL_DATABASE_SCHEMA_COLUMN_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* This recognizes native CREATE TABLE text, not arbitrary SQL equivalence. */
static inline bool dbsc_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
}

static inline bool dbsc_ident(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

static inline char dbsc_lower(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c + ('a' - 'A')) : c;
}

static inline bool dbsc_name_equal(const char *p, size_t n, const char *name)
{
    if (strlen(name) != n) return false;
    for (size_t i = 0; i < n; ++i)
        if (dbsc_lower(p[i]) != dbsc_lower(name[i])) return false;
    return true;
}

/* Consume one quoted token. Doubled delimiters follow SQLite spelling. */
static inline bool dbsc_quote(const char **at)
{
    char open = **at, end = open == '[' ? ']' : open;
    const char *p = *at + 1;
    while (*p) {
        if (*p++ != end) continue;
        if (open != '[' && *p == end) { ++p; continue; }
        *at = p;
        return true;
    }
    return false;
}

static inline bool dbsc_quote_start(char c)
{
    return c == 39 || c == '"' || c == '`' || c == '[';
}

static inline bool dbsc_forbidden(const char *p)
{
    return (p[0] == '-' && p[1] == '-') ||
           (p[0] == '/' && p[1] == '*') || *p == ';';
}

/* Stop at an unquoted comma or closing parenthesis at field depth zero. */
static inline bool dbsc_field_end(const char **at)
{
    const char *p = *at;
    unsigned depth = 0;
    while (*p) {
        if (dbsc_quote_start(*p)) {
            if (!dbsc_quote(&p)) return false;
        } else if (dbsc_forbidden(p)) {
            return false;
        } else if (*p == '(') {
            if (depth == 1024) return false;
            ++depth; ++p;
        } else if (*p == ')') {
            if (!depth) { *at = p; return true; }
            --depth; ++p;
        } else if (*p == ',' && !depth) {
            *at = p; return true;
        } else {
            ++p;
        }
    }
    return false;
}

static inline bool dbsc_tail(const char *p)
{
    while (dbsc_space(*p)) ++p;
    if (strncmp(p, "WITHOUT ROWID", 13) == 0) p += 13;
    else if (strncmp(p, "STRICT", 6) == 0) p += 6;
    while (dbsc_space(*p)) ++p;
    if (*p == ';') { ++p; while (dbsc_space(*p)) ++p; }
    return *p == '\0';
}

static inline bool dbsc_request_valid(const char *schema, const char *name,
                                      const char *declaration)
{
    if (!schema || !name || !*name || !declaration || !*declaration) return false;
    if (strncmp(schema, "CREATE TABLE ", 13) != 0) return false;
    for (const char *n = name; *n; ++n) if (!dbsc_ident(*n)) return false;
    size_t len = strlen(name);
    return strncmp(declaration, name, len) == 0 && dbsc_space(declaration[len]);
}

static inline const char *dbsc_first_field(const char *schema)
{
    const char *p = schema + 13;
    if (!dbsc_ident(*p)) return NULL;
    while (dbsc_ident(*p)) ++p;
    while (dbsc_space(*p)) ++p;
    return *p == '(' ? p + 1 : NULL;
}

static inline bool dbsc_field_match(const char *start, const char *end,
                                    const char *declaration)
{
    while (end > start && dbsc_space(end[-1])) --end;
    size_t n = (size_t)(end - start);
    return n == strlen(declaration) && memcmp(start, declaration, n) == 0;
}

static inline bool dbsc_fields(const char *p, const char *name,
                               const char *declaration)
{
    bool matched = false;
    for (;;) {
        while (dbsc_space(*p)) ++p;
        const char *start = p;
        while (dbsc_ident(*p)) ++p;
        if (p == start || (!dbsc_space(*p) && *p != '(')) return false;
        bool same = dbsc_name_equal(start, (size_t)(p - start), name);
        if (!dbsc_field_end(&p)) return false;
        if (same) {
            if (matched || !dbsc_field_match(start, p, declaration)) return false;
            matched = true;
        }
        if (*p++ == ')') return matched && dbsc_tail(p);
    }
}

/* Match one complete top-level native declaration and reject ambiguity. */
static inline bool db_schema_column_exact(const char *schema, const char *name,
                                          const char *declaration)
{
    if (!dbsc_request_valid(schema, name, declaration)) return false;
    const char *p = dbsc_first_field(schema);
    return p && dbsc_fields(p, name, declaration);
}
#endif
