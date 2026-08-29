/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * grok_report — pull the one report object out of a grok transcript.
 *
 * tools/dev/grok-unit.sh asks a dispatched unit to finish by printing a
 * single JSON object describing what it did. That object arrives buried in a
 * transcript: sometimes as a real node in the JSON the engine emits, more
 * often as TEXT inside an assistant message, because the engine is quoting
 * the model rather than parsing it. Both shapes are handled here.
 *
 * WHY THIS IS NOT A jq ONE-LINER. Nothing in this project takes a dependency
 * it did not write, and that rule does not get an exception for developer
 * tooling -- a tool that only runs on machines with jq installed is a tool
 * that does not run on a stranger's machine. The JSON parser is already in
 * this tree; this is thirty lines of walking it.
 *
 * The report is the MODEL DESCRIBING ITSELF and is never evidence that
 * anything works. grok-unit.sh prints it for a human and then judges the
 * unit by running its test group. Read it as a claim, not as a result.
 *
 * Usage: grok_report <transcript-file> [key]
 *   Prints the first object carrying `key` (default "files_touched").
 *   Exit 0 if one was found, 1 if none, 2 on a usage or read error.
 */

#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Does this object carry the marker key at its top level? */
static bool has_key(const struct json_value *v, const char *key)
{
    return v && v->type == JSON_OBJ && json_get(v, key) != NULL;
}

static void print_value(const struct json_value *v)
{
    size_t need = json_write(v, NULL, 0);
    char *buf = malloc(need + 1);
    if (!buf) {
        fprintf(stderr, "grok_report: out of memory for a %zu byte report\n",
                need + 1);
        return;
    }
    if (json_write(v, buf, need + 1) < need + 1)
        printf("%s\n", buf);
    free(buf);
}

/* A JSON object printed as prose inside a string. Scan for a balanced brace
 * run that parses AND carries the marker: the first '{' in a chatty message
 * is often the start of an example, not the report, so a run that fails to
 * parse must not end the search. Braces inside string literals do not count
 * toward the depth, or a report mentioning a path with a brace would cut
 * itself short. */
static bool find_in_text(const char *s, const char *key)
{
    for (const char *open = strchr(s, '{'); open; open = strchr(open + 1, '{')) {
        int depth = 0;
        bool in_str = false, escaped = false;
        for (const char *p = open; *p; p++) {
            if (escaped)            { escaped = false; continue; }
            if (*p == '\\')         { escaped = true;  continue; }
            if (*p == '"')          { in_str = !in_str; continue; }
            if (in_str)             continue;
            if (*p == '{')          depth++;
            else if (*p == '}' && --depth == 0) {
                struct json_value v;
                json_init(&v);
                size_t len = (size_t)(p - open) + 1;
                if (json_read(&v, open, len) && has_key(&v, key)) {
                    print_value(&v);
                    json_free(&v);
                    return true;
                }
                json_free(&v);
                break;  /* this run closed and was not it; try the next '{' */
            }
        }
    }
    return false;
}

static bool walk(const struct json_value *v, const char *key)
{
    if (!v)
        return false;
    if (has_key(v, key)) {
        print_value(v);
        return true;
    }
    if (v->type == JSON_STR) {
        const char *s = json_get_str(v);
        return s && find_in_text(s, key);
    }
    for (size_t i = 0; i < v->num_children; i++)
        if (walk(&v->children[i], key))
            return true;
    return false;
}

/* The transcript may be one JSON document or one per line. Try the whole
 * file first; a single document is the common case and parsing it once keeps
 * an object that spans lines intact. */
static bool scan(char *text, size_t len, const char *key)
{
    struct json_value v;
    json_init(&v);
    if (json_read(&v, text, len)) {
        bool found = walk(&v, key);
        json_free(&v);
        if (found)
            return true;
    } else {
        json_free(&v);
    }

    for (char *line = text, *end; line < text + len; line = end + 1) {
        end = memchr(line, '\n', (size_t)(text + len - line));
        if (!end)
            end = text + len;
        size_t line_len = (size_t)(end - line);
        if (line_len == 0)
            continue;
        json_init(&v);
        bool ok = json_read(&v, line, line_len) && walk(&v, key);
        json_free(&v);
        if (ok)
            return true;
        if (end == text + len)
            break;
    }
    return false;
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <transcript-file> [key]\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];
    const char *key = (argc == 3) ? argv[2] : "files_touched";

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "grok_report: cannot read %s\n", path);
        return 2;
    }
    size_t cap = 1 << 16, len = 0;
    char *text = malloc(cap);
    if (!text) {
        fclose(f);
        fprintf(stderr, "grok_report: out of memory\n");
        return 2;
    }
    for (;;) {
        if (len == cap) {
            size_t want = cap * 2;
            char *bigger = realloc(text, want);
            if (!bigger) {
                free(text);
                fclose(f);
                fprintf(stderr, "grok_report: transcript too large\n");
                return 2;
            }
            text = bigger;
            cap = want;
        }
        size_t got = fread(text + len, 1, cap - len, f);
        len += got;
        if (got == 0)
            break;
    }
    fclose(f);

    bool found = scan(text, len, key);
    free(text);
    return found ? 0 : 1;
}
