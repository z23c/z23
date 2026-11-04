/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Build tool: inspect rendered HTML files for common issues.
 * Usage: inspect_html <file.html> [checks...]
 *
 * Checks:
 *   --count <pattern>     Count occurrences of pattern
 *   --has <pattern>       Exit 0 if pattern found, 1 if not
 *   --no <pattern>        Exit 0 if pattern NOT found, 1 if found
 *   --text                Strip tags, print visible text
 *   --unresolved          Check for unresolved {{vars}} outside <script> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "util/safe_alloc.h"

static char *read_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz <= 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char *buf = zcl_malloc((size_t)sz + 1, "inspect_html read_file buf");
    if (!buf) { fclose(f); return NULL; }
    size_t len = fread(buf, 1, (size_t)sz, f);
    int extra = fgetc(f);
    /* Every check uses C strings: a NUL must not silently hide the suffix. */
    bool invalid = len != (size_t)sz || extra != EOF || ferror(f) ||
                   memchr(buf, '\0', len);
    if (fclose(f) != 0) invalid = true;
    if (invalid) { free(buf); return NULL; }
    *len_out = len;
    buf[len] = '\0';
    return buf;
}

static int count_pattern(const char *hay, const char *needle) {
    int n = 0;
    size_t nlen = strlen(needle);
    /* An empty needle matches at every position (strstr(p, "") == p), so
     * advancing by nlen makes no progress and the loop spins forever —
     * count zero instead. */
    if (nlen == 0)
        return 0;
    const char *p = hay;
    while ((p = strstr(p, needle)) != NULL) { n++; p += nlen; }
    return n;
}

static void print_text(const char *html) {
    bool in_tag = false, in_style = false, in_script = false;
    for (size_t i = 0; html[i]; i++) {
        if (html[i] == '<') {
            in_tag = true;
            if (strncmp(html + i, "<style", 6) == 0) in_style = true;
            if (strncmp(html + i, "<script", 7) == 0) in_script = true;
            if (strncmp(html + i, "</style", 7) == 0) in_style = false;
            if (strncmp(html + i, "</script", 8) == 0) in_script = false;
            continue;
        }
        if (html[i] == '>') { in_tag = false; continue; }
        if (!in_tag && !in_style && !in_script) {
            if (html[i] == '&') {
                /* Skip HTML entities */
                const char *semi = strchr(html + i, ';');
                if (semi && semi - (html + i) < 10) { i = (size_t)(semi - html); continue; }
            }
            putchar(html[i]);
        }
    }
    putchar('\n');
}

static bool check_unresolved(const char *html) {
    const char *p = html;
    while (*p) {
        /* Skip <script>...</script> blocks */
        if (strncmp(p, "<script", 7) == 0) {
            const char *end = strstr(p, "</script>");
            if (end) { p = end + 9; continue; }
        }
        /* Check for {{ that isn't {{{ */
        if (p[0] == '{' && p[1] == '{' && p[2] != '{') {
            /* Found unresolved template variable */
            char var[64] = "";
            const char *close = strstr(p + 2, "}}");
            if (close) {
                size_t vlen = (size_t)(close - p - 2);
                if (vlen < sizeof(var)) {
                    memcpy(var, p + 2, vlen);
                    var[vlen] = '\0';
                }
            }
            fprintf(stderr, "UNRESOLVED: {{%s}}\n", var);
            return true;
        }
        p++;
    }
    return false;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <file> --count|--has|--no|--text|--unresolved [pattern]\n",
            argv[0]);
        return 2;
    }

    size_t len = 0;
    char *html = read_file(argv[1], &len);
    if (!html) {
        fprintf(stderr, "Cannot read complete HTML text (I/O error or embedded NUL): %s\n", argv[1]);
        return 2;
    }

    int rc = 0;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            printf("%d\n", count_pattern(html, argv[++i]));
        } else if (strcmp(argv[i], "--has") == 0 && i + 1 < argc) {
            if (!strstr(html, argv[++i])) rc = 1;
        } else if (strcmp(argv[i], "--no") == 0 && i + 1 < argc) {
            if (strstr(html, argv[++i])) rc = 1;
        } else if (strcmp(argv[i], "--text") == 0) {
            print_text(html);
        } else if (strcmp(argv[i], "--unresolved") == 0) {
            if (check_unresolved(html)) rc = 1;
        }
    }

    free(html);
    return rc;
}
