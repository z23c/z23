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
#include <errno.h>

#if defined(_WIN32)
#include <direct.h>
#include <process.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "util/safe_alloc.h"
#include "platform/path_replace.h"

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

/* CSS whitespace, and the structural characters that absorb the whitespace
 * beside them. */
static bool css_space(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static bool css_structural(char c) {
    return c == '{' || c == '}' || c == ':' || c == ';' || c == ',' || c == '>';
}

/* True when a block comment opens at src[i]. */
static bool css_comment_open(const char *src, size_t src_len, size_t i) {
    return i + 1 < src_len && src[i] == '/' && src[i + 1] == '*';
}

/* Return the index just past the block comment that opens at src[i]. */
static size_t skip_css_comment(const char *src, size_t src_len, size_t i) {
    i += 2;
    while (i + 1 < src_len && !(src[i] == '*' && src[i + 1] == '/')) i++;
    if (i + 1 < src_len) i += 2;
    return i;
}

/* Update string state for the quote character at src[i]. */
static void track_css_quote(const char *src, size_t i, bool *in_string,
                            char *string_char) {
    if (!*in_string) {
        *in_string = true;
        *string_char = src[i];
    } else if (src[i] == *string_char && (i == 0 || src[i - 1] != '\\')) {
        *in_string = false;
    }
}

/* Collapse the whitespace run at src[i] into at most one space in out.
 * The space is dropped beside a structural character. Returns the index just
 * past the run; *w is the output length and is advanced. */
static size_t collapse_css_space(const char *src, size_t src_len, size_t i,
                                 char *out, size_t *w) {
    bool skip = *w > 0 && css_structural(out[*w - 1]);
    while (i < src_len && css_space(src[i])) i++;
    if (i < src_len && css_structural(src[i])) skip = true;
    if (!skip && *w > 0 && i < src_len)
        out[(*w)++] = ' ';
    return i;
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
        if (!in_string && css_comment_open(src, src_len, i)) {
            i = skip_css_comment(src, src_len, i);
            continue;
        }
        /* Track strings to avoid mangling them */
        if (src[i] == '\'' || src[i] == '"') {
            track_css_quote(src, i, &in_string, &string_char);
            out[w++] = src[i++];
            continue;
        }
        if (in_string) {
            out[w++] = src[i++];
            continue;
        }
        /* Collapse whitespace */
        if (css_space(src[i])) {
            i = collapse_css_space(src, src_len, i, out, &w);
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
 * no-op regeneration leave no trace. The stage must not live beside the
 * tracked header: source identity inventories every transient beneath source
 * roots, and independent Make processes otherwise race on the same `.tmp`.
 * Each invocation therefore exclusively owns one unique stage beneath the
 * ignored, same-filesystem build/identity directory. Sorted output (see
 * process_dir) is what makes "no-op" actually reachable across machines; the
 * three properties go together. */
static FILE *open_staged(const char *out_path, char *tmp_path, size_t tmp_cap)
{
    static unsigned int sequence;
    if (!out_path || !out_path[0] || !tmp_path || tmp_cap == 0)
        return NULL;
#if defined(_WIN32)
    if (_mkdir("build/identity") != 0 && errno != EEXIST)
        return NULL;
#else
    if (mkdir("build/identity", 0700) != 0 && errno != EEXIST)
        return NULL;
#endif
#if defined(_WIN32)
    const long process_id = (long)_getpid();
#else
    const long process_id = (long)getpid();
#endif
    for (unsigned int attempt = 0; attempt < 256u; ++attempt) {
        unsigned int serial = ++sequence;
        int n = snprintf(tmp_path, tmp_cap,
                         "build/identity/.gen_templates-stage.%ld.%u",
                         process_id, serial);
        if (n < 0 || (size_t)n >= tmp_cap)
            return NULL;
        FILE *stage = fopen(tmp_path, "wx");
        if (stage)
            return stage;
        if (errno != EEXIST)
            return NULL;
    }
    return NULL;
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
    if (platform_path_replace(tmp_path, out_path) != 0) {
        remove(tmp_path);
        return 1;
    }
    *out_changed = true;
    return 0;
}

/* Close whichever selftest stages opened and remove their files. */
static void discard_selftest_stages(FILE *a, const char *stage_a,
                                    FILE *b, const char *stage_b)
{
    if (a) (void)fclose(a);
    if (b) (void)fclose(b);
    if (a) (void)remove(stage_a);
    if (b && (!a || strcmp(stage_a, stage_b) != 0))
        (void)remove(stage_b);
}

/* The destination must hold exactly the second stage's bytes, both stages
 * must have been committed (changed), and neither stage file may survive. */
static bool selftest_outcome_ok(bool changed_a, bool changed_b,
                                const char *destination,
                                const char *stage_a, const char *stage_b)
{
    size_t length = 0;
    char *bytes = read_file(destination, &length);
    bool ok = changed_a && changed_b && bytes && length == 7u &&
              memcmp(bytes, "second\n", 7u) == 0;
    free(bytes);
    return ok && read_file(stage_a, &length) == NULL &&
           read_file(stage_b, &length) == NULL;
}

/* Deterministic KAT for the race that a timing-only parallel test can miss:
 * two stages for one destination must coexist and commit independent bytes.
 * The old `<output>.tmp` implementation fails before either close because the
 * two returned pathnames are identical. */
static int staging_selftest(void)
{
    char destination[256], stage_a[256], stage_b[256];
#if defined(_WIN32)
    const long process_id = (long)_getpid();
#else
    const long process_id = (long)getpid();
#endif
    int n = snprintf(destination, sizeof(destination),
                     "build/identity/.gen_templates-selftest.%ld", process_id);
    if (n < 0 || (size_t)n >= sizeof(destination))
        return 1;
    (void)remove(destination);

    FILE *a = open_staged(destination, stage_a, sizeof(stage_a));
    FILE *b = open_staged(destination, stage_b, sizeof(stage_b));
    if (!a || !b || strcmp(stage_a, stage_b) == 0) {
        discard_selftest_stages(a, stage_a, b, stage_b);
        fprintf(stderr, "gen_templates: staging selftest lacks distinct exclusive stages\n");
        return 1;
    }
    if (fputs("first\n", a) < 0 || fputs("second\n", b) < 0) {
        (void)fclose(a);
        (void)fclose(b);
        (void)remove(stage_a);
        (void)remove(stage_b);
        return 1;
    }
    bool changed_a = false, changed_b = false;
    int commit_a = commit_staged(a, stage_a, destination, &changed_a);
    int commit_b = commit_staged(b, stage_b, destination, &changed_b);
    if (commit_a != 0 || commit_b != 0) {
        (void)remove(stage_a);
        (void)remove(stage_b);
        (void)remove(destination);
        return 1;
    }
    bool ok = selftest_outcome_ok(changed_a, changed_b, destination,
                                  stage_a, stage_b);
    (void)remove(destination);
    fprintf(stderr, "gen_templates: staging selftest %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
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

/* Embed one file byte-for-byte (no minification — a shell script's
 * whitespace and newlines are load-bearing) as a chunked C string plus a
 * `%s_get()` accessor, same shape as write_single_css_header above. */
static int write_single_text_header(const char *src_path, const char *out_path,
                                    const char *symbol, const char *guard)
{
    size_t src_len = 0;
    char *src = NULL;
    FILE *out = NULL;
    int chunks = 0;
    size_t chunk_size = 3000;

    if (!valid_c_identifier(symbol) || !valid_c_identifier(guard)) {
        fprintf(stderr, "gen_templates: invalid C identifier\n");
        return 1;
    }

    src = read_file(src_path, &src_len);
    if (!src) {
        fprintf(stderr, "gen_templates: cannot read: %s\n", src_path);
        return 1;
    }

    char tmp_path[1200];
    out = open_staged(out_path, tmp_path, sizeof(tmp_path));
    if (!out) {
        fprintf(stderr, "gen_templates: cannot write: %s\n", out_path);
        free(src);
        return 1;
    }

    fprintf(out,
        "/* Auto-generated from %s -- do not edit.\n"
        " * Regenerate: make templates */\n\n"
        "#ifndef %s\n"
        "#define %s\n\n",
        src_path, guard, guard);

    for (size_t off = 0; off < src_len; off += chunk_size) {
        size_t clen = src_len - off;
        if (clen > chunk_size)
            clen = chunk_size;
        fprintf(out, "static const char %s_%d[] =\n", symbol, chunks);
        write_c_string(out, src + off, clen);
        fprintf(out, ";\n");
        chunks++;
    }
    if (chunks == 0) {
        fprintf(out, "static const char %s_0[] = \"\";\n", symbol);
        chunks = 1;
    }

    fprintf(out, "\nstatic char _%s_buf[%zu];\n", symbol, src_len + 1);
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
        free(src);
        return 1;
    }
    free(src);
    fprintf(stderr, "gen_templates: text %s -> %s (%zu bytes, %s)\n",
            src_path, out_path, src_len,
            changed ? "updated" : "unchanged");
    return 0;
}

/* Order two directory entries by name, so the emitted header depends on the
 * template SET and never on the filesystem that stored it. */
static int name_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* Collect the names in dir that end with ext and fit the name buffer, in
 * readdir order. Exits on overflow of MAX_TEMPLATES. */
static size_t collect_dir_names(DIR *d, const char *dir, const char *ext,
                                char (*names)[256]) {
    size_t ext_len = strlen(ext);
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
    return n_names;
}

/* Record a template for the partial registry. CSS is never tracked, and the
 * table stops growing at MAX_TEMPLATES. Names are truncated to their slots. */
static void track_template_name(const char *name_base, const char *name_upper,
                                bool minify) {
    if (minify || tmpl_name_count >= MAX_TEMPLATES) return;
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

enum { TEMPLATE_DIR_UNAVAILABLE = -1, TEMPLATE_INPUT_UNREADABLE = -2 };

static int process_dir(const char *dir, const char *ext, const char *prefix,
                       bool minify, bool required_read, FILE *out) {
    DIR *d = opendir(dir);
    if (!d) return TEMPLATE_DIR_UNAVAILABLE;

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
    size_t n_names = collect_dir_names(d, dir, ext, names);
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
            if (required_read) {
                fprintf(stderr, "gen_templates: cannot read template %s\n", path);
                return TEMPLATE_INPUT_UNREADABLE;
            }
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
        track_template_name(name_base, name_upper, minify);

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

/* Single-header modes: argv[1] selects the writer, and its usage tail is
 * printed when the argument count is wrong. */
struct single_mode {
    const char *flag;
    const char *usage;
    int (*write)(const char *src, const char *out, const char *symbol,
                 const char *guard);
};

static const struct single_mode single_modes[] = {
    { "--single-css", "--single-css <input.css> <output.h> <symbol> <guard>",
      write_single_css_header },
    { "--single-text", "--single-text <input> <output.h> <symbol> <guard>",
      write_single_text_header },
};

/* Returns false when argv names no single-header mode, so main falls through
 * to the directory mode. Otherwise stores the exit code in *rc. */
static bool run_single_mode(int argc, char **argv, int *rc) {
    for (size_t i = 0; i < sizeof(single_modes) / sizeof(single_modes[0]); i++) {
        if (argc < 2 || strcmp(argv[1], single_modes[i].flag) != 0)
            continue;
        if (argc != 6) {
            fprintf(stderr, "Usage: %s %s\n", argv[0], single_modes[i].usage);
            *rc = 1;
        } else {
            *rc = single_modes[i].write(argv[2], argv[3], argv[4], argv[5]);
        }
        return true;
    }
    return false;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--selftest-staging") == 0)
        return staging_selftest();
    int single_rc = 0;
    if (run_single_mode(argc, argv, &single_rc))
        return single_rc;

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

    int tmpl_count = process_dir(tmpl_dir, ".chtml", "TMPL", false, true, out);
    if (tmpl_count < 0) {
        if (tmpl_count == TEMPLATE_DIR_UNAVAILABLE)
            fprintf(stderr, "gen_templates: cannot open template directory %s: %s\n",
                    tmpl_dir, strerror(errno));
        (void)fclose(out);
        (void)remove(tmp_path);
        return 1;
    }

    int css_count = 0;
    if (css_dir)
        css_count = process_dir(css_dir, ".ccss", "CSS", true, false, out);
    if (css_count < 0) css_count = 0;

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
