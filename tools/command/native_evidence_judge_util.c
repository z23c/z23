/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Line-level JSON field readers and report-text helpers shared by
 *          the soak and stopwatch judges. */

#include "native_evidence_judge_util.h"

#include "base/safe_alloc.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EJ_KEY_MAX 64

static bool ej_needle(const char *key, char *needle, size_t cap)
{
    return snprintf(needle, cap, "\"%s\":", key) < (int)cap;
}

static bool ej_integer_end(char c)
{
    return c == 0 || c == ',' || c == '}' || c == ']' ||
           c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* Parses `-?[0-9]+` at p. */
static bool ej_parse_int(const char *p, int64_t *n)
{
    const char *digits = p[0] == '-' ? p + 1 : p;
    char *end;
    if (digits[0] < '0' || digits[0] > '9')
        return false;
    errno = 0;
    long long value = strtoll(p, &end, 10);
    if (errno == ERANGE || value < INT64_MIN || value > INT64_MAX || end == p ||
        !ej_integer_end(*end))
        return false;
    *n = (int64_t)value;
    return true;
}

struct ej_num ej_field_num(const char *line, const char *key, bool allow_null)
{
    struct ej_num r = {EJ_MISSING, 0};
    char needle[EJ_KEY_MAX];
    const char *p = line;
    if (!ej_needle(key, needle, sizeof(needle)))
        return r;
    while ((p = strstr(p, needle)) != NULL) {
        p += strlen(needle);
        if (allow_null && strncmp(p, "null", 4) == 0) {
            r.kind = EJ_NULL;
            return r;
        }
        if (ej_parse_int(p, &r.n)) {
            r.kind = EJ_NUM;
            return r;
        }
    }
    return r;
}

bool ej_field_str(const char *line, const char *key, char *out, size_t cap)
{
    char needle[EJ_KEY_MAX];
    const char *p = line;
    if (!ej_needle(key, needle, sizeof(needle)) || cap == 0)
        return false;
    while ((p = strstr(p, needle)) != NULL) {
        const char *end;
        p += strlen(needle);
        if (*p != '"')
            continue;
        end = strchr(p + 1, '"');
        if (!end)
            continue;
        (void)snprintf(out, cap, "%.*s", (int)(end - p - 1), p + 1);
        return true;
    }
    return false;
}

void ej_cat(struct zcl_judge_result *out, const char *fmt, ...)
{
    size_t at = strlen(out->text);
    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(out->text + at, sizeof(out->text) - at, fmt, args);
    va_end(args);
}

void ej_verdict(struct zcl_judge_result *out, int exit_code, const char *verdict,
                const char *reason)
{
    out->exit_code = exit_code;
    (void)snprintf(out->verdict, sizeof(out->verdict), "%s", verdict);
    (void)snprintf(out->reason, sizeof(out->reason), "%s", reason);
}

int64_t ej_now(int64_t given)
{
    return given > 0 ? given : (int64_t)platform_time_wall_time_t();
}

char *ej_slurp(const char *path, size_t max, size_t *len)
{
    FILE *f = fopen(path, "rb");
    char *buf = NULL;
    long size;
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) <= 0 ||
        (size_t)size > max || fseek(f, 0, SEEK_SET) != 0) {
        (void)fclose(f);
        return NULL;
    }
    buf = zcl_malloc((size_t)size + 1, "judge ledger");
    if (buf && fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        buf = NULL;
    }
    (void)fclose(f);
    if (buf) {
        buf[size] = '\0';
        *len = (size_t)size;
    }
    return buf;
}

int ej_env_int(const char *name, const char *text, int64_t *value, char *err,
               size_t err_cap)
{
    if (!text || !text[0])
        return 0;
    for (const char *p = text; *p; p++) {
        if (*p < '0' || *p > '9') {
            (void)snprintf(err, err_cap,
                           "%s must be a non-negative integer (got '%s')", name,
                           text);
            return -1;
        }
    }
    *value = (int64_t)strtoll(text, NULL, 10);
    return 1;
}
