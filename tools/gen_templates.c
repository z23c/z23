/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Build tool: converts .chtml and .css files into a C header.
 * Each foo.chtml becomes: static const char TMPL_FOO[] = "...";
 * Each bar.ccss becomes:  static const char CSS_BAR[] = "..."; (minified)
 * .ccss files support {{var}} and {{{var}}} template variables.
 *
 * Usage: gen_templates <template_dir> <output.h> [css_dir]
 * Example: gen_templates contexts/explorer/views/templates contexts/wallet/views/include/views/wallet_templates_gen.h contexts/explorer/views/css */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <dirent.h>
#include <ctype.h>

#include "util/safe_alloc.h"

#define MAX_KEY_LEN 64
#define MAX_FILE_SIZE (256 * 1024)

static void to_upper_underscore(const char *in, char *out, size_t max) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j < max - 1; i++) {
        if (in[i] == '-' || in[i] == '.')
            out[j++] = '_';
        else
            out[j++] = (char)toupper((unsigned char)in[i]);
    }
    out[j] = '\0';
}

/* Validate filename: alphanumeric + hyphens only (before extension) */
static bool valid_filename(const char *name, size_t base_len) {
    for (size_t i = 0; i < base_len; i++) {
        char c = name[i];
        if (!isalnum((unsigned char)c) && c != '-')
            return false;
    }
    return base_len > 0 && base_len <= MAX_KEY_LEN;
}

/* Read file into malloc'd buffer with NUL termination. Returns NULL on error. */
static char *read_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > MAX_FILE_SIZE) { fclose(f); return NULL; }
    char *buf = zcl_malloc((size_t)fsize + 1, "gen_templates read_file buf");
    if (!buf) { fclose(f); return NULL; }
    size_t nread = fread(buf, 1, (size_t)fsize, f);
    buf[nread] = '\0';
    fclose(f);
    /* Binary file protection: reject NUL bytes */
    for (size_t i = 0; i < nread; i++) {
        if (buf[i] == '\0') { free(buf); return NULL; }
    }
    *len_out = nread;
    return buf;
}

/* Write a C string literal (escaped).
 * Splits into multiple concatenated string literals every ~3000 chars
 * to stay under the C99 4095-char minimum string literal length. */
static void write_c_string(FILE *out, const char *buf, size_t len) {
    fprintf(out, "    \"");
    int col = 4;
    int str_len = 0;  /* Current string literal length */
    for (size_t i = 0; i < len; i++) {
        /* Split into new string literal before hitting C99 limit */
        if (str_len > 3000) {
            fprintf(out, "\"\n    \"");
            col = 4;
            str_len = 0;
        }
        /* Line wrap for readability */
        if (col > 100) {
            fprintf(out, "\"\n    \"");
            col = 4;
        }
        switch (buf[i]) {
        case '\\': fputs("\\\\", out); col += 2; str_len += 2; break;
        case '"':  fputs("\\\"", out); col += 2; str_len += 2; break;
        case '\n': fputs("\\n", out);  col += 2; str_len += 2; break;
        case '\r': break;
        case '\t': fputs("\\t", out);  col += 2; str_len += 2; break;
        default:   fputc(buf[i], out); col += 1; str_len += 1; break;
        }
    }
    fprintf(out, "\"");
}

/* Minify CSS: strip comments, collapse whitespace, remove spaces around
 * structural characters. Output goes to malloc'd buffer. */
static char *minify_css(const char *src, size_t src_len, size_t *out_len) {
    char *out = zcl_malloc(src_len + 1, "gen_templates minify_css buf");
    if (!out) return NULL;
    size_t w = 0;
    bool in_string = false;
    char string_char = 0;

    for (size_t i = 0; i < src_len; ) {
        /* Skip block comments */
        if (!in_string && i + 1 < src_len && src[i] == '/' && src[i+1] == '*') {
            i += 2;
            while (i + 1 < src_len && !(src[i] == '*' && src[i+1] == '/')) i++;
            if (i + 1 < src_len) i += 2;
            continue;
        }
        /* Track strings to avoid mangling them */
        if (src[i] == '\'' || src[i] == '"') {
            if (!in_string) {
                in_string = true;
                string_char = src[i];
            } else if (src[i] == string_char && (i == 0 || src[i-1] != '\\')) {
                in_string = false;
            }
            out[w++] = src[i++];
            continue;
        }
        if (in_string) {
            out[w++] = src[i++];
            continue;
        }
        /* Collapse whitespace */
        if (src[i] == ' ' || src[i] == '\t' || src[i] == '\n' || src[i] == '\r') {
            /* Skip whitespace entirely if adjacent to structural chars */
            bool skip = false;
            if (w > 0) {
                char prev = out[w-1];
                if (prev == '{' || prev == '}' || prev == ':' ||
                    prev == ';' || prev == ',' || prev == '>')
                    skip = true;
            }
            /* Skip leading whitespace */
            while (i < src_len && (src[i] == ' ' || src[i] == '\t' ||
                                   src[i] == '\n' || src[i] == '\r')) i++;
            /* Check next char */
            if (i < src_len) {
                char next = src[i];
                if (next == '{' || next == '}' || next == ':' ||
                    next == ';' || next == ',' || next == '>')
                    skip = true;
            }
            if (!skip && w > 0 && i < src_len)
                out[w++] = ' ';
            continue;
        }
        out[w++] = src[i++];
    }
    out[w] = '\0';
    *out_len = w;
    return out;
}

/* Track template names for partial registry */
#define MAX_TEMPLATES 256
static struct { char base[128]; char upper[128]; } tmpl_names[MAX_TEMPLATES];
static int tmpl_name_count = 0;

/* Process a directory of files with given extension.
 * prefix: "TMPL" for .chtml, "CSS" for .css
 * minify: true for .css files
 * track: true to add to partial registry */
static bool valid_c_identifier(const char *s) {
    if (!s || (!isalpha((unsigned char)s[0]) && s[0] != '_'))
        return false;
    for (size_t i = 1; s[i]; i++) {
        if (!isalnum((unsigned char)s[i]) && s[i] != '_')
            return false;
    }
    return true;
}

/* ── Write-if-changed ─────────────────────────────────────────────────
 *
 * These headers are TRACKED files that the build produces, and the build's
 * source-identity guard hashes the mtime/ctime of every tracked source. A
 * fresh clone has to compile this generator first, which leaves the tool
 * newer than the committed header, so make re-runs the rule on every first
 * build. Rewriting the file then moves the source identity out from under
 * the in-flight build and the link is refused outright:
 *
 *     source-identity: source build superseded: expected=.../mutation=...
 *
 * That is a fresh clone failing its first `make`, on every machine. Emitting
 * to a temporary and replacing the target only when the BYTES differ makes a
 * no-op regeneration leave no trace. Sorted output (see process_dir) is what
 * makes "no-op" actually reachable across machines; the two go together. */
static FILE *open_staged(const char *out_path, char *tmp_path, size_t tmp_cap)
{
    int n = snprintf(tmp_path, tmp_cap, "%s.tmp", out_path);
    if (n < 0 || (size_t)n >= tmp_cap) return NULL;
    return fopen(tmp_path, "w");
}

/* Close the staged file and move it over out_path only if the contents
 * changed. Returns 0 on success, 1 on I/O failure. */
static int commit_staged(FILE *out, const char *tmp_path, const char *out_path,
                         bool *out_changed)
{
    *out_changed = false;
    if (fclose(out) != 0) { remove(tmp_path); return 1; }

    size_t new_len = 0, old_len = 0;
    char *new_buf = read_file(tmp_path, &new_len);
    if (!new_buf) { remove(tmp_path); return 1; }
    char *old_buf = read_file(out_path, &old_len);

    bool same = old_buf && new_len == old_len &&
                memcmp(new_buf, old_buf, new_len) == 0;
    free(new_buf);
    free(old_buf);

    if (same) {
        remove(tmp_path);
        return 0;
    }
    if (rename(tmp_path, out_path) != 0) { remove(tmp_path); return 1; }
    *out_changed = true;
    return 0;
}

static int write_single_css_header(const char *src_path, const char *out_path,
                                   const char *symbol, const char *guard)
{
    size_t src_len = 0;
    size_t min_len = 0;
    char *src = NULL;
    char *minified = NULL;
    FILE *out = NULL;
    int chunks = 0;
    size_t chunk_size = 3000;

    if (!valid_c_identifier(symbol) || !valid_c_identifier(guard)) {
        fprintf(stderr, "gen_templates: invalid C identifier\n");
        return 1;
    }

    src = read_file(src_path, &src_len);
    if (!src) {
        fprintf(stderr, "gen_templates: cannot read CSS: %s\n", src_path);
        return 1;
    }
    minified = minify_css(src, src_len, &min_len);
    free(src);
    if (!minified)
        return 1;

    char tmp_path[1200];
    out = open_staged(out_path, tmp_path, sizeof(tmp_path));
    if (!out) {
        fprintf(stderr, "gen_templates: cannot write: %s\n", out_path);
        free(minified);
        return 1;
    }

    fprintf(out,
        "/* Auto-generated from %s -- do not edit.\n"
        " * Regenerate: make site-css */\n\n"
        "#ifndef %s\n"
        "#define %s\n\n",
        src_path, guard, guard);

    for (size_t off = 0; off < min_len; off += chunk_size) {
        size_t clen = min_len - off;
        if (clen > chunk_size)
            clen = chunk_size;
        fprintf(out, "static const char %s_%d[] =\n", symbol, chunks);
        write_c_string(out, minified + off, clen);
        fprintf(out, ";\n");
        chunks++;
    }

    fprintf(out, "\nstatic char _%s_buf[%zu];\n", symbol, min_len + 1);
    fprintf(out,
        "__attribute__((unused))\n"
        "static const char *%s_get(void) {\n"
        "    size_t off = 0;\n",
        symbol);
    for (int c = 0; c < chunks; c++) {
        fprintf(out,
            "    size_t l%d = __builtin_strlen(%s_%d);\n"
            "    __builtin_memcpy(_%s_buf + off, %s_%d, l%d); off += l%d;\n",
            c, symbol, c, symbol, symbol, c, c, c);
    }
    fprintf(out,
        "    _%s_buf[off] = 0;\n"
        "    return _%s_buf;\n"
        "}\n"
        "#define %s (%s_get())\n\n"
        "#endif\n",
        symbol, symbol, symbol, symbol);

    bool changed = false;
    if (commit_staged(out, tmp_path, out_path, &changed) != 0) {
        fprintf(stderr, "gen_templates: cannot write: %s\n", out_path);
        free(minified);
        return 1;
    }
    free(minified);
    fprintf(stderr, "gen_templates: CSS %s -> %s (%zu bytes, %s)\n",
            src_path, out_path, min_len,
            changed ? "updated" : "unchanged");
    return 0;
}

/* Order two directory entries by name, so the emitted header depends on the
 * template SET and never on the filesystem that stored it. */
static int name_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int process_dir(const char *dir, const char *ext, const char *prefix,
                       bool minify, FILE *out) {
    DIR *d = opendir(dir);
    if (!d) return 0;

    int count = 0;
    size_t ext_len = strlen(ext);

    /* Collect the matching names, THEN sort, THEN emit.
     *
     * readdir returns entries in filesystem order. That order is not stable
     * across machines, and not even across two checkouts on one machine —
     * it follows directory inode layout. This generator writes a TRACKED
     * header, so an unsorted walk means the first build in a fresh clone
     * rewrites a committed file with the same 49 templates in a different
     * order: the tree goes dirty and the build's own source-identity guard
     * kills the link. That is a fresh clone failing its first `make`, and it
     * also makes a byte-identical two-builder result impossible by
     * construction. Sorting is the whole fix. */
    static char names[MAX_TEMPLATES][256];
    size_t n_names = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        size_t nlen = strlen(ent->d_name);
        if (nlen <= ext_len ||
            strcmp(ent->d_name + nlen - ext_len, ext) != 0)
            continue;
        if (nlen >= sizeof(names[0])) {
            fprintf(stderr, "gen_templates: skipping over-long name: %s\n",
                ent->d_name);
            continue;
        }
        if (n_names >= MAX_TEMPLATES) {
            fprintf(stderr, "gen_templates: FATAL more than %d '%s' files in "
                "%s — raise MAX_TEMPLATES\n", MAX_TEMPLATES, ext, dir);
            closedir(d);
            exit(1);
        }
        memcpy(names[n_names], ent->d_name, nlen + 1);
        n_names++;
    }
    closedir(d);
    qsort(names, n_names, sizeof(names[0]), name_cmp);

    for (size_t ni = 0; ni < n_names; ni++) {
        const char *d_name = names[ni];
        size_t nlen = strlen(d_name);

        size_t base_len = nlen - ext_len;
        if (!valid_filename(d_name, base_len)) {
            fprintf(stderr, "gen_templates: skipping invalid name: %s\n",
                d_name);
            continue;
        }

        char path[1024];
        int plen = snprintf(path, sizeof(path), "%s/%s", dir, d_name);
        if (plen < 0 || (size_t)plen >= sizeof(path)) {
            fprintf(stderr, "gen_templates: skipping over-long path: %s/%s\n",
                dir, d_name);
            continue;
        }

        size_t flen = 0;
        char *buf = read_file(path, &flen);
        if (!buf) {
            fprintf(stderr, "gen_templates: skipping %s\n", d_name);
            continue;
        }

        /* Convert filename to C identifier */
        char name_base[256];
        snprintf(name_base, sizeof(name_base), "%.*s",
            (int)base_len, d_name);
        char name_upper[256];
        to_upper_underscore(name_base, name_upper, sizeof(name_upper));

        /* Track for partial registry (templates only, not CSS) */
        if (!minify && tmpl_name_count < MAX_TEMPLATES) {
            size_t base_copy = strlen(name_base);
            size_t upper_copy = strlen(name_upper);
            if (base_copy >= sizeof(tmpl_names[tmpl_name_count].base))
                base_copy = sizeof(tmpl_names[tmpl_name_count].base) - 1;
            if (upper_copy >= sizeof(tmpl_names[tmpl_name_count].upper))
                upper_copy = sizeof(tmpl_names[tmpl_name_count].upper) - 1;
            memcpy(tmpl_names[tmpl_name_count].base, name_base, base_copy);
            tmpl_names[tmpl_name_count].base[base_copy] = '\0';
            memcpy(tmpl_names[tmpl_name_count].upper, name_upper, upper_copy);
            tmpl_names[tmpl_name_count].upper[upper_copy] = '\0';
            tmpl_name_count++;
        }

        if (minify) {
            size_t min_len = 0;
            char *minified = minify_css(buf, flen, &min_len);
            free(buf);
            if (!minified) continue;
            /* Split large CSS into multiple arrays to avoid
             * -Woverlength-strings (C99 requires support for 4095). */
            int chunks = 0;
            size_t chunk_size = 3000;
            for (size_t off = 0; off < min_len; off += chunk_size) {
                size_t clen = min_len - off;
                if (clen > chunk_size) clen = chunk_size;
                fprintf(out, "static const char %s_%s_%d[] =\n",
                    prefix, name_upper, chunks);
                write_c_string(out, minified + off, clen);
                fprintf(out, ";\n");
                chunks++;
            }
            /* Concatenation function */
            fprintf(out, "static char _%s_%s_buf[%zu];\n",
                prefix, name_upper, min_len + 1);
            fprintf(out,
                "__attribute__((unused))\n"
                "static const char *%s_%s_get(void) {\n",
                prefix, name_upper);
            fprintf(out, "    size_t off = 0;\n");
            for (int c = 0; c < chunks; c++) {
                fprintf(out,
                    "    size_t l%d = __builtin_strlen(%s_%s_%d);\n"
                    "    __builtin_memcpy(_%s_%s_buf + off, %s_%s_%d, l%d);"
                    " off += l%d;\n",
                    c, prefix, name_upper, c,
                    prefix, name_upper, prefix, name_upper, c, c, c);
            }
            fprintf(out, "    _%s_%s_buf[off] = 0;\n", prefix, name_upper);
            fprintf(out, "    return _%s_%s_buf;\n", prefix, name_upper);
            fprintf(out, "}\n");
            fprintf(out, "#define %s_%s (%s_%s_get())\n\n",
                prefix, name_upper, prefix, name_upper);
            free(minified);
        } else {
            fprintf(out, "static const char %s_%s[] =\n", prefix, name_upper);
            write_c_string(out, buf, flen);
            fprintf(out, ";\n\n");
            free(buf);
        }
        count++;
    }
    return count;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--single-css") == 0) {
        if (argc != 6) {
            fprintf(stderr,
                "Usage: %s --single-css <input.css> <output.h> <symbol> <guard>\n",
                argv[0]);
            return 1;
        }
        return write_single_css_header(argv[2], argv[3], argv[4], argv[5]);
    }

    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s <template_dir> <output.h> [css_dir]\n",
            argv[0]);
        return 1;
    }

    const char *tmpl_dir = argv[1];
    const char *out_path = argv[2];
    const char *css_dir = (argc >= 4) ? argv[3] : NULL;

    char tmp_path[1200];
    FILE *out = open_staged(out_path, tmp_path, sizeof(tmp_path));
    if (!out) {
        fprintf(stderr, "Cannot write: %s\n", out_path);
        return 1;
    }

    fprintf(out,
        "/* Auto-generated from .chtml and .css files -- do not edit.\n"
        " * Regenerate: make templates */\n\n"
        "#ifndef ZCL_VIEWS_WALLET_TEMPLATES_GEN_H\n"
        "#define ZCL_VIEWS_WALLET_TEMPLATES_GEN_H\n\n");

    int tmpl_count = process_dir(tmpl_dir, ".chtml", "TMPL", false, out);

    int css_count = 0;
    if (css_dir)
        css_count = process_dir(css_dir, ".ccss", "CSS", true, out);

    /* Generate partial registry for {{> name}} lookups */
    fprintf(out, "#include \"util/template.h\"\n\n");
    fprintf(out,
        "static const struct template_partial _tmpl_partials[] = {\n");
    for (int i = 0; i < tmpl_name_count; i++) {
        fprintf(out, "    { \"%s\", TMPL_%s },\n",
            tmpl_names[i].base, tmpl_names[i].upper);
    }
    fprintf(out, "};\n\n");
    fprintf(out,
        "#define TMPL_PARTIAL_COUNT %d\n\n"
        "__attribute__((unused))\n"
        "static void tmpl_init_partials(void) {\n"
        "    template_register_partials(_tmpl_partials, TMPL_PARTIAL_COUNT);\n"
        "}\n\n",
        tmpl_name_count);

    fprintf(out, "#endif\n");

    bool changed = false;
    if (commit_staged(out, tmp_path, out_path, &changed) != 0) {
        fprintf(stderr, "Cannot write: %s\n", out_path);
        return 1;
    }

    fprintf(stderr, "gen_templates: %d .chtml + %d .ccss files -> %s (%s)\n",
        tmpl_count, css_count, out_path, changed ? "updated" : "unchanged");
    return 0;
}
