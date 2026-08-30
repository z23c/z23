/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fp_index — the source scanner behind behavioral fingerprinting.
 *
 * It reads every tracked .c/.h, blanks comments and literals in place (so a
 * cleaned offset is still an original offset and still on the original
 * line), then walks the file at brace/paren depth zero recording, per
 * top-level construct: function DEFINITIONS with their body span, function
 * PROTOTYPES with the header that declares them, `#define`s with their
 * replacement text, file-scope OBJECTS with whether they are const, and
 * enumeration CONSTANTS.
 *
 * This is a scanner, not a compiler. It does not evaluate the preprocessor.
 * Where that matters it errs toward seeing MORE code — text inside an
 * inactive `#if` is scanned as if it were live — because for a purity
 * judgement that fails closed, seeing extra code can only cause a rejection,
 * never a wrong acceptance.
 */

#include "fp_priv.h"

#include "base/safe_alloc.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define FP_SYMS_INITIAL 8192u

bool fp_ident_start(int c) { return isalpha(c) || c == '_'; }
bool fp_ident_char(int c) { return isalnum(c) || c == '_'; }

uint64_t fp_hash_str(const char *s)
{
    uint64_t h = 1469598103934665603ull;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 1099511628211ull;
    }
    return h;
}

static uint64_t fp_hash_mem(const char *s, size_t n)
{
    uint64_t h = 1469598103934665603ull;
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ull;
    }
    return h;
}

int fp_line_of(const struct fp_file *f, uint32_t off)
{
    size_t i;
    int line = 1;
    size_t lim = off < f->len ? off : f->len;
    for (i = 0; i < lim; i++)
        if (f->text[i] == '\n')
            line++;
    return line;
}

int fp_sym_lookup(const struct fp_index *ix, const char *name, size_t len,
                  enum fp_sym_kind kind)
{
    uint64_t h;
    int i;
    if (len >= FP_MAX_NAME)
        return -1;
    h = fp_hash_mem(name, len);
    for (i = ix->bucket[h % ix->nbuckets]; i >= 0; i = ix->syms[i].next) {
        const struct fp_sym *s = &ix->syms[i];
        if (s->kind != (unsigned char)kind)
            continue;
        if (strlen(s->name) == len && memcmp(s->name, name, len) == 0)
            return i;
    }
    return -1;
}

/* ── file loading and cleaning ───────────────────────────────────────── */

static void fp_derive_group(const char *path, char *out, size_t cap)
{
    const char *slash1 = strchr(path, '/');
    const char *slash2 = slash1 ? strchr(slash1 + 1, '/') : NULL;
    size_t n;
    if (slash1 == NULL) {
        snprintf(out, cap, "%s", "root");
        return;
    }
    if (strncmp(path, "lib/", 4) == 0 || strncmp(path, "app/", 4) == 0 ||
        strncmp(path, "domain/", 7) == 0 || strncmp(path, "core/", 5) == 0 ||
        strncmp(path, "application/", 12) == 0) {
        if (slash2 == NULL) {
            n = (size_t)(slash1 - path);
        } else {
            n = (size_t)(slash2 - path);
        }
    } else {
        n = (size_t)(slash1 - path);
    }
    if (n >= cap)
        n = cap - 1u;
    memcpy(out, path, n);
    out[n] = '\0';
}

static void fp_derive_include(const char *path, char *out, size_t cap)
{
    const char *inc = strstr(path, "/include/");
    if (inc != NULL)
        snprintf(out, cap, "%s", inc + 9);
    else
        snprintf(out, cap, "%s", path);
}

/* Blank comments and string/char literals to spaces, keeping newlines and
 * every byte offset. Line splices are left alone; a `\`-continued line still
 * reads as one logical line to the directive scanner below. */
static void fp_clean(char *t, size_t n)
{
    size_t i = 0;
    while (i < n) {
        char c = t[i];
        if (c == '/' && i + 1 < n && t[i + 1] == '/') {
            while (i < n && t[i] != '\n') t[i++] = ' ';
        } else if (c == '/' && i + 1 < n && t[i + 1] == '*') {
            t[i] = ' '; t[i + 1] = ' '; i += 2;
            while (i < n) {
                if (t[i] == '*' && i + 1 < n && t[i + 1] == '/') {
                    t[i] = ' '; t[i + 1] = ' '; i += 2; break;
                }
                if (t[i] != '\n') t[i] = ' ';
                i++;
            }
        } else if (c == '"' || c == '\'') {
            char q = c;
            t[i++] = ' ';
            while (i < n && t[i] != q) {
                if (t[i] == '\\' && i + 1 < n) {
                    t[i] = ' ';
                    i++;
                    if (t[i] != '\n') t[i] = ' ';
                    i++;
                    continue;
                }
                if (t[i] == '\n') break;
                t[i] = ' ';
                i++;
            }
            if (i < n && t[i] == q) t[i++] = ' ';
        } else {
            i++;
        }
    }
}

static bool fp_load(struct fp_index *ix, const char *root, const char *rel)
{
    struct fp_file *f = &ix->files[ix->nfiles];
    char full[FP_MAX_PATH * 2];
    FILE *fh;
    long sz;
    size_t got;

    if (strlen(rel) >= FP_MAX_PATH)
        return true;                       /* silently out of scope */
    snprintf(full, sizeof full, "%s/%s", root, rel);
    fh = fopen(full, "rb");
    if (fh == NULL)
        return true;                       /* a listed file that is gone */
    if (fseek(fh, 0, SEEK_END) != 0) { fclose(fh); return true; }
    sz = ftell(fh);
    if (sz < 0 || sz > 64L * 1024L * 1024L) { fclose(fh); return true; }
    if (fseek(fh, 0, SEEK_SET) != 0) { fclose(fh); return true; }
    f->text = (char *)zcl_malloc((size_t)sz + 1u, "fp.file");
    if (f->text == NULL) { fclose(fh); return false; }
    got = fread(f->text, 1, (size_t)sz, fh);
    fclose(fh);
    f->text[got] = '\0';
    f->len = got;
    fp_clean(f->text, f->len);
    snprintf(f->path, sizeof f->path, "%s", rel);
    fp_derive_group(rel, f->group, sizeof f->group);
    fp_derive_include(rel, f->include, sizeof f->include);
    f->is_header = strlen(rel) > 2u && strcmp(rel + strlen(rel) - 2, ".h") == 0;
    ix->nfiles++;
    return true;
}

/* ── symbol table ────────────────────────────────────────────────────── */

static bool fp_sym_push(struct fp_index *ix, const struct fp_sym *proto)
{
    struct fp_sym *s;
    uint64_t h;
    if (ix->nsyms == ix->syms_cap) {
        size_t ncap = ix->syms_cap * 2u;
        struct fp_sym *grown =
            (struct fp_sym *)zcl_realloc(ix->syms, ncap * sizeof *grown, "fp.syms");
        if (grown == NULL)
            return false;
        ix->syms = grown;
        ix->syms_cap = ncap;
    }
    s = &ix->syms[ix->nsyms];
    *s = *proto;
    s->verdict = -1;
    h = fp_hash_str(s->name);
    s->next = ix->bucket[h % ix->nbuckets];
    ix->bucket[h % ix->nbuckets] = (int)ix->nsyms;
    ix->nsyms++;
    if (s->kind == (unsigned char)FP_SYM_FUNC)
        ix->nfuncs++;
    return true;
}

static size_t fp_skip_ws(const char *t, size_t i, size_t n)
{
    while (i < n && (isspace((unsigned char)t[i]) || t[i] == '\\'))
        i++;
    return i;
}

/* Skip a balanced group starting at t[i] == open. Returns the index just
 * past the matching close, or n on imbalance. */
static size_t fp_skip_group(const char *t, size_t i, size_t n, char open,
                            char close)
{
    int depth = 0;
    for (; i < n; i++) {
        if (t[i] == open) depth++;
        else if (t[i] == close) { depth--; if (depth == 0) return i + 1u; }
    }
    return n;
}

static void fp_copy_name(char *dst, const char *src, size_t len)
{
    if (len >= FP_MAX_NAME)
        len = FP_MAX_NAME - 1u;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* Record every enumeration constant inside an `enum { ... }` body. Constants
 * are compile-time integers and are always safe to read. */
static bool fp_scan_enum_body(struct fp_index *ix, int file, size_t start,
                              size_t end)
{
    const char *t = ix->files[file].text;
    size_t i = start;
    bool expect_name = true;
    while (i < end) {
        if (t[i] == '=') {
            while (i < end && t[i] != ',') i++;
            expect_name = true;
            continue;
        }
        if (t[i] == ',') { expect_name = true; i++; continue; }
        if (fp_ident_start((unsigned char)t[i])) {
            size_t j = i;
            while (j < end && fp_ident_char((unsigned char)t[j])) j++;
            if (expect_name) {
                struct fp_sym s = {0};
                fp_copy_name(s.name, t + i, j - i);
                s.kind = (unsigned char)FP_SYM_ENUMCONST;
                s.file = file;
                s.line = 0;
                if (!fp_sym_push(ix, &s))
                    return false;
                expect_name = false;
            }
            i = j;
            continue;
        }
        i++;
    }
    return true;
}

/* A `#define`. Records the macro name and its replacement text so the
 * purity walk can look THROUGH it — a body that calls LOG_ERROR() is impure
 * because of what LOG_ERROR expands to, and refusing to expand would either
 * accept it wrongly or reject every macro in the tree. */
static size_t fp_scan_define(struct fp_index *ix, int file, size_t i,
                             size_t n, bool *ok)
{
    const char *t = ix->files[file].text;
    size_t name_s;
    size_t name_e;
    size_t body_s;
    size_t end;
    struct fp_sym s = {0};

    i = fp_skip_ws(t, i, n);
    if (i >= n || !fp_ident_start((unsigned char)t[i]))
        return i;
    name_s = i;
    while (i < n && fp_ident_char((unsigned char)t[i])) i++;
    name_e = i;
    if (i < n && t[i] == '(')
        i = fp_skip_group(t, i, n, '(', ')');
    body_s = i;
    end = i;
    while (end < n) {
        if (t[end] == '\\') {
            end++;
            while (end < n && t[end] != '\n') end++;
            if (end < n) end++;
            continue;
        }
        if (t[end] == '\n') break;
        end++;
    }
    fp_copy_name(s.name, t + name_s, name_e - name_s);
    s.kind = (unsigned char)FP_SYM_MACRO;
    s.file = file;
    s.body_off = (uint32_t)body_s;
    s.body_len = (uint32_t)(end - body_s);
    if (!fp_sym_push(ix, &s))
        *ok = false;
    return end;
}

/* Does this declarator text name a function, and if so where? Returns the
 * offset of the parameter-list open paren and fills name_s and name_e,
 * or SIZE_MAX when the segment is not a plain function declarator. Anything
 * involving a function-pointer declarator (`(*f)(…)`) is deliberately NOT a
 * plain function declarator here; those are refused later by name. */
/* Skip whitespace and any `__attribute__((…))` groups. */
static size_t fp_skip_attrs(const char *t, size_t i, size_t n)
{
    i = fp_skip_ws(t, i, n);
    while (i + 13u < n && strncmp(t + i, "__attribute__", 13) == 0) {
        i = fp_skip_group(t, fp_skip_ws(t, i + 13u, n), n, '(', ')');
        i = fp_skip_ws(t, i, n);
    }
    return i;
}

static size_t fp_find_declarator(const char *t, size_t s, size_t e, size_t n,
                                 size_t *name_s, size_t *name_e,
                                 size_t *decl_start)
{
    size_t i = s;
    *decl_start = s;
    while (i < e) {
        size_t j;
        size_t k;
        size_t rp;
        size_t after;
        if (t[i] == '[') { i = fp_skip_group(t, i, e, '[', ']'); continue; }
        if (t[i] != '(') { i++; continue; }
        j = i;
        while (j > *decl_start && isspace((unsigned char)t[j - 1])) j--;
        k = j;
        while (k > *decl_start && fp_ident_char((unsigned char)t[k - 1])) k--;
        rp = fp_skip_group(t, i, n, '(', ')');
        after = fp_skip_attrs(t, rp, n);
        if (k < j && after < n && (t[after] == '{' || t[after] == ';')) {
            *name_s = k;
            *name_e = j;
            return i;
        }
        /* Not the parameter list. A bare X-macro invocation at file scope
         * (`DEFINE_MODEL_CALLBACKS(explorer)` with no semicolon) sits in
         * front of the next real declaration, so the declarator restarts
         * after it instead of swallowing it — before this, one such macro
         * desynchronised the rest of the file. */
        *decl_start = rp;
        i = rp;
    }
    return (size_t)-1;
}

/* Is the file-scope object safe for a pure function to read? Only when the
 * declaration is const-qualified at the OUTERMOST level: `static const T
 * x[]` lands in read-only storage and cannot change under us, while `static
 * const char *x[]` is an array of MUTABLE pointers and does not. */
static bool fp_object_is_const(const char *t, size_t s, size_t name_s)
{
    size_t i;
    size_t last_star = (size_t)-1;
    bool const_after = false;
    for (i = s; i < name_s; i++)
        if (t[i] == '*')
            last_star = i;
    for (i = (last_star == (size_t)-1) ? s : last_star + 1u; i + 5u <= name_s;
         i++) {
        if (strncmp(t + i, "const", 5) == 0 &&
            (i == s || !fp_ident_char((unsigned char)t[i - 1])) &&
            !fp_ident_char((unsigned char)t[i + 5])) {
            const_after = true;
            break;
        }
    }
    return const_after;
}

/* The declared name at the end of an object declarator, skipping any
 * trailing array extents. Returns false when the segment declares nothing
 * nameable (a bare `struct x;`, an attribute salad). */
static bool fp_object_name(const char *t, size_t s, size_t e, size_t *ns,
                           size_t *ne)
{
    while (e > s && isspace((unsigned char)t[e - 1])) e--;
    while (e > s && t[e - 1] == ']') {
        int d = 0;
        size_t br = e;
        while (br > s) {
            br--;
            if (t[br] == ']') d++;
            else if (t[br] == '[') { d--; if (d == 0) break; }
        }
        if (br == s) return false;
        e = br;
        while (e > s && isspace((unsigned char)t[e - 1])) e--;
    }
    *ne = e;
    while (e > s && fp_ident_char((unsigned char)t[e - 1])) e--;
    *ns = e;
    return *ne > *ns;
}

static bool fp_segment_has_static(const char *t, size_t s, size_t e)
{
    size_t i;
    for (i = s; i + 6u <= e; i++) {
        if (strncmp(t + i, "static", 6) == 0 &&
            (i == s || !fp_ident_char((unsigned char)t[i - 1])) &&
            !fp_ident_char((unsigned char)t[i + 6]))
            return true;
    }
    return false;
}

static bool fp_scan_file(struct fp_index *ix, int file)
{
    struct fp_file *f = &ix->files[file];
    const char *t = f->text;
    size_t n = f->len;
    size_t i = 0;
    bool ok = true;

    while (i < n) {
        size_t seg_s;
        size_t j;
        bool at_line_start;
        size_t k;

        i = fp_skip_ws(t, i, n);
        if (i >= n) break;

        at_line_start = true;
        for (k = i; k > 0; k--) {
            if (t[k - 1] == '\n') break;
            if (!isspace((unsigned char)t[k - 1])) { at_line_start = false; break; }
        }
        if (t[i] == '#' && at_line_start) {
            size_t d = fp_skip_ws(t, i + 1u, n);
            if (d + 6u <= n && strncmp(t + d, "define", 6) == 0 &&
                !fp_ident_char((unsigned char)t[d + 6])) {
                i = fp_scan_define(ix, file, d + 6u, n, &ok);
                if (!ok) return false;
                continue;
            }
            while (i < n) {
                if (t[i] == '\\') {
                    i++;
                    while (i < n && t[i] != '\n') i++;
                    if (i < n) i++;
                    continue;
                }
                if (t[i] == '\n') { i++; break; }
                i++;
            }
            continue;
        }
        if (t[i] == ';') { i++; continue; }

        seg_s = i;
        j = i;
        while (j < n) {
            char c = t[j];
            if (c == '#') {                       /* a directive mid-segment */
                while (j < n && t[j] != '\n') j++;
                continue;
            }
            if (c == '(') { j = fp_skip_group(t, j, n, '(', ')'); continue; }
            if (c == '[') { j = fp_skip_group(t, j, n, '[', ']'); continue; }
            if (c == ';' || c == '{' || c == '=') break;
            j++;
        }
        if (j >= n) break;

        if (t[j] == '=') {                        /* object with initialiser */
            struct fp_sym s = {0};
            size_t ns = 0;
            size_t ne = 0;
            if (fp_object_name(t, seg_s, j, &ns, &ne)) {
                fp_copy_name(s.name, t + ns, ne - ns);
                s.kind = (unsigned char)FP_SYM_OBJ;
                s.file = file;
                s.const_object = fp_object_is_const(t, seg_s, ns);
                s.is_static = fp_segment_has_static(t, seg_s, ns);
                if (!fp_sym_push(ix, &s)) return false;
            }
            /* step over the initialiser to its terminating ';' */
            {
                int d2 = 0;
                size_t p = j;
                for (; p < n; p++) {
                    if (t[p] == '{') d2++;
                    else if (t[p] == '}') d2--;
                    else if (t[p] == ';' && d2 == 0) { p++; break; }
                }
                i = p;
            }
            continue;
        }

        {
            size_t name_s = 0;
            size_t name_e = 0;
            size_t dstart = seg_s;
            size_t lp = fp_find_declarator(t, seg_s, j, n, &name_s, &name_e,
                                           &dstart);
            bool is_func = false;
            if (lp != (size_t)-1) {
                size_t rp = fp_skip_group(t, lp, n, '(', ')');
                size_t after = fp_skip_attrs(t, rp, n);
                {
                    struct fp_sym s = {0};
                    fp_copy_name(s.name, t + name_s, name_e - name_s);
                    s.file = file;
                    s.decl_off = (uint32_t)dstart;
                    s.decl_len = (uint32_t)(rp - dstart);
                    s.is_static = fp_segment_has_static(t, dstart, name_s);
                    if (t[after] == '{') {
                        size_t be = fp_skip_group(t, after, n, '{', '}');
                        s.kind = (unsigned char)FP_SYM_FUNC;
                        s.body_off = (uint32_t)after;
                        s.body_len = (uint32_t)(be - after);
                        s.line = fp_line_of(f, (uint32_t)dstart);
                        i = be;
                    } else {
                        s.kind = (unsigned char)FP_SYM_PROTO;
                        s.line = fp_line_of(f, (uint32_t)dstart);
                        i = after + 1u;
                    }
                    if (!fp_sym_push(ix, &s)) return false;
                    is_func = true;
                }
            }
            if (is_func)
                continue;
        }

        if (t[j] == '{') {                         /* aggregate or enum body */
            size_t be = fp_skip_group(t, j, n, '{', '}');
            size_t p;
            bool is_enum = false;
            for (p = seg_s; p + 4u <= j; p++) {
                if (strncmp(t + p, "enum", 4) == 0 &&
                    (p == seg_s || !fp_ident_char((unsigned char)t[p - 1])) &&
                    !fp_ident_char((unsigned char)t[p + 4])) {
                    is_enum = true;
                    break;
                }
            }
            if (is_enum && !fp_scan_enum_body(ix, file, j + 1u, be - 1u))
                return false;
            /* Resume immediately after the aggregate, consuming only a
             * semicolon that actually follows it. Hunting forward for the
             * next `;` used to run straight into the NEXT function's body
             * and desynchronise the rest of the file. */
            p = fp_skip_ws(t, be, n);
            if (p < n && t[p] == ';')
                i = p + 1u;
            else
                i = be;
            continue;
        }

        {                                           /* a plain declaration */
            struct fp_sym s = {0};
            size_t ns = 0;
            size_t ne = 0;
            bool is_typedef = (j - seg_s > 7u &&
                               strncmp(t + seg_s, "typedef", 7) == 0 &&
                               !fp_ident_char((unsigned char)t[seg_s + 7]));
            if (fp_object_name(t, seg_s, j, &ns, &ne)) {
                /* `struct x;` / `union x;` / `enum x;` declares a TAG, not an
                 * object. Filing a forward declaration as a mutable global
                 * made every function mentioning that type name read as
                 * impure — 550 of them, before this test existed. */
                size_t q = ns;
                bool tag_only;
                while (q > seg_s && isspace((unsigned char)t[q - 1])) q--;
                tag_only = (q - seg_s == 6u && strncmp(t + seg_s, "struct", 6) == 0) ||
                           (q - seg_s == 5u && strncmp(t + seg_s, "union", 5) == 0) ||
                           (q - seg_s == 4u && strncmp(t + seg_s, "enum", 4) == 0);
                fp_copy_name(s.name, t + ns, ne - ns);
                s.file = file;
                if (tag_only) {
                    s.kind = (unsigned char)FP_SYM_TYPE;
                    s.decl_off = (uint32_t)seg_s;
                    s.decl_len = 0u;
                } else if (is_typedef) {
                    /* Recorded with its declarator text so fp_sig can walk
                     * one alias at a time down to a real scalar spelling. */
                    s.kind = (unsigned char)FP_SYM_TYPE;
                    s.decl_off = (uint32_t)seg_s;
                    s.decl_len = (uint32_t)(j - seg_s);
                } else {
                    s.kind = (unsigned char)FP_SYM_OBJ;
                    s.const_object = fp_object_is_const(t, seg_s, ns);
                    s.is_static = fp_segment_has_static(t, seg_s, ns);
                }
                if (!fp_sym_push(ix, &s)) return false;
            }
            i = j + 1u;
        }
    }
    return true;
}

/* ── public build/teardown ───────────────────────────────────────────── */

struct fp_index *fp_index_build(const char *root, const char *const *files,
                                size_t n_files)
{
    struct fp_index *ix;
    size_t i;

    ix = (struct fp_index *)zcl_calloc(1, sizeof *ix, "fp.index");
    if (ix == NULL)
        return NULL;
    snprintf(ix->root, sizeof ix->root, "%s", root);
    ix->allow_source_route = true;
    ix->files = (struct fp_file *)zcl_calloc(n_files ? n_files : 1u,
                                             sizeof *ix->files, "fp.files");
    ix->nbuckets = 1u << 17;
    ix->bucket = (int *)zcl_malloc(ix->nbuckets * sizeof *ix->bucket, "fp.bucket");
    ix->syms_cap = FP_SYMS_INITIAL;
    ix->syms = (struct fp_sym *)zcl_malloc(ix->syms_cap * sizeof *ix->syms, "fp.syms");
    if (ix->files == NULL || ix->bucket == NULL || ix->syms == NULL) {
        fp_index_free(ix);
        return NULL;
    }
    for (i = 0; i < ix->nbuckets; i++)
        ix->bucket[i] = -1;

    for (i = 0; i < n_files; i++) {
        if (!fp_load(ix, root, files[i])) {
            fp_index_free(ix);
            return NULL;
        }
    }
    for (i = 0; i < ix->nfiles; i++) {
        if (!fp_scan_file(ix, (int)i)) {
            fp_index_free(ix);
            return NULL;
        }
    }
    /* Mark the units that own a main(). A probe translation unit that
     * included one would define main() twice — once from the tree, once from
     * the generated driver — and the whole link would fail rather than one
     * candidate. Refusing them at scan time keeps that a NAMED exclusion. */
    for (i = 0; i < ix->nsyms; i++) {
        const struct fp_sym *s = &ix->syms[i];
        if (s->kind == (unsigned char)FP_SYM_FUNC &&
            strcmp(s->name, "main") == 0 && s->file >= 0 &&
            (size_t)s->file < ix->nfiles)
            ix->files[s->file].defines_main = true;
    }
    /* Mark the units that export a symbol some other unit also exports. See
     * fp_file.dup_export: these are the `#if`-guarded platform twins, and
     * including two of them into two probe TUs is a link failure, not a
     * probe failure. Quadratic only in the hash chain, which is short. */
    for (i = 0; i < ix->nsyms; i++) {
        const struct fp_sym *s = &ix->syms[i];
        uint64_t h;
        int j;
        if (s->kind != (unsigned char)FP_SYM_FUNC || s->is_static)
            continue;
        if (ix->files[s->file].is_header || ix->files[s->file].dup_export)
            continue;
        h = fp_hash_str(s->name);
        for (j = ix->bucket[h % ix->nbuckets]; j >= 0; j = ix->syms[j].next) {
            const struct fp_sym *o = &ix->syms[j];
            if (o == s || o->kind != (unsigned char)FP_SYM_FUNC ||
                o->is_static || o->file == s->file)
                continue;
            if (ix->files[o->file].is_header)
                continue;
            if (strcmp(o->name, s->name) != 0)
                continue;
            ix->files[s->file].dup_export = true;
            ix->files[o->file].dup_export = true;
            break;
        }
    }
    return ix;
}

void fp_index_free(struct fp_index *ix)
{
    size_t i;
    if (ix == NULL)
        return;
    for (i = 0; i < ix->nfiles; i++)
        free(ix->files[i].text);
    free(ix->files);
    free(ix->syms);
    free(ix->bucket);
    free(ix);
}

size_t fp_index_function_count(const struct fp_index *ix)
{
    return ix->nfuncs;
}

void fp_index_allow_source_route(struct fp_index *ix, bool on)
{
    ix->allow_source_route = on;
}

const char *fp_verdict_text(enum fp_verdict v)
{
    static const char *const text[] = {
#define FP_VERDICT_TEXT(id_, str_) str_,
        FP_VERDICT_TABLE(FP_VERDICT_TEXT)
#undef FP_VERDICT_TEXT
    };
    if ((int)v < 0 || (int)v >= FP_V_COUNT)
        return "unknown";
    return text[(int)v];
}
