/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Read the authored command registry text (outside generator-owned
 *          blocks) so a manifest can be checked for collisions with it. Names
 *          are found by lexical scan only; nothing is preprocessed. */

#define _POSIX_C_SOURCE 200809L

#include "toolgen.h"

#include "base/safe_alloc.h"

#include <ctype.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define DEF_DIR "engine/composition/commands"
#define HEADER_DIR "tools/command"
#define TEXT_LIMIT (4u * 1024u * 1024u)
#define HANDLER_PREFIX "zcl_native_handle_"

bool tg_names_add(struct tg_names *s, const char *name, size_t len)
{
    if (s->n == s->cap) {
        size_t cap = s->cap ? s->cap * 2u : 64u;
        char **v = zcl_realloc(s->v, cap * sizeof *v, "toolgen.names");
        if (!v)
            return false;
        s->v = v;
        s->cap = cap;
    }
    char *copy = zcl_malloc(len + 1u, "toolgen.name");
    if (!copy)
        return false;
    memcpy(copy, name, len);
    copy[len] = '\0';
    s->v[s->n++] = copy;
    return true;
}

bool tg_names_has(const struct tg_names *s, const char *name)
{
    for (size_t i = 0; i < s->n; i++)
        if (strcmp(s->v[i], name) == 0)
            return true;
    return false;
}

void tg_names_free(struct tg_names *s)
{
    for (size_t i = 0; i < s->n; i++)
        free(s->v[i]);
    free(s->v);
    *s = (struct tg_names){0};
}

static int cmp_names(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

void tg_names_sort(struct tg_names *s)
{
    qsort(s->v, s->n, sizeof *s->v, cmp_names);
}

void tg_world_free(struct tg_world *w)
{
    tg_names_free(&w->paths);
    tg_names_free(&w->branches);
    tg_names_free(&w->handlers);
    tg_names_free(&w->remote);
    tg_names_free(&w->groups);
}

static bool read_text(const char *root, const char *rel, struct tg_sb *out, struct tg_err *e)
{
    char path[1024];
    if (!tg_join(path, sizeof path, root, rel))
        return tg_fail(e, "IO_ERROR", "path too long: %s", rel);
    switch (tg_read_file(path, TEXT_LIMIT, out)) {
    case TG_READ_OK:
        return true;
    case TG_READ_NOT_REGULAR:
        return tg_fail(e, "SOURCE_NOT_REGULAR", "%s is not a regular file", rel);
    case TG_READ_TOO_LARGE:
        return tg_fail(e, "SOURCE_TOO_LARGE", "%s exceeds %u bytes", rel, TEXT_LIMIT);
    default:
        return tg_fail(e, "IO_ERROR", "cannot read %s", rel);
    }
}

static const char *owned_id(const char *rel)
{
    struct tg_target t[TG_MAX_TARGETS];
    size_t n = tg_targets(t, TG_MAX_TARGETS);
    for (size_t i = 0; i < n; i++)
        if (strcmp(rel, t[i].path) == 0)
            return t[i].id;
    return NULL;
}

/* Reads rel and removes its generator-owned block, if the file has one. */
static bool read_authored(const char *root, const char *rel, struct tg_sb *out, struct tg_err *e)
{
    struct tg_sb raw = {0};
    if (!read_text(root, rel, &raw, e)) {
        tg_sb_free(&raw);
        return false;
    }
    const char *id = owned_id(rel);
    struct tg_block b;
    bool ok = true;
    if (id) {
        ok = tg_block_locate(raw.p, raw.n, id, rel, &b, e) &&
             tg_block_splice(raw.p, raw.n, &b, "", 0, out);
    } else {
        tg_sb_putn(out, raw.p, raw.n);
    }
    tg_sb_free(&raw);
    return ok && !out->oom;
}

static bool is_idc(unsigned char c)
{
    return isalnum(c) || c == '_';
}

/* Copies the macro name that starts at pos; returns the offset after it, or 0. */
static size_t macro_name(const char *t, size_t len, size_t pos, const char *prefix, char *macro,
                         size_t mcap)
{
    size_t pl = strlen(prefix);
    if (pos + pl > len || memcmp(t + pos, prefix, pl) != 0)
        return 0;
    size_t k = pos;
    while (k < len && is_idc((unsigned char)t[k]))
        k++;
    if (k - pos >= mcap)
        return 0;
    memcpy(macro, t + pos, k - pos);
    macro[k - pos] = '\0';
    return k;
}

static size_t skip_space(const char *t, size_t len, size_t k)
{
    while (k < len && isspace((unsigned char)t[k]))
        k++;
    return k;
}

/* Reads `(  "literal"` at k: the literal's bytes, without the quotes. */
static bool first_literal(const char *t, size_t len, size_t k, const char **lit, size_t *llen)
{
    k = skip_space(t, len, k);
    if (k >= len || t[k] != '(')
        return false;
    k = skip_space(t, len, k + 1u);
    if (k >= len || t[k] != '"')
        return false;
    *lit = t + k + 1u;
    size_t j = k + 1u;
    while (j < len && t[j] != '"' && t[j] != '\n')
        j++;
    *llen = j - (k + 1u);
    return j < len && t[j] == '"';
}

/* Column-0 `PREFIX...(  "literal"`: returns the literal and the macro name. */
static bool row_literal(const char *t, size_t len, size_t pos, const char *prefix,
                        char *macro, size_t mcap, const char **lit, size_t *llen)
{
    size_t k = macro_name(t, len, pos, prefix, macro, mcap);
    return k != 0 && first_literal(t, len, k, lit, llen);
}

static bool collect_rows(const struct tg_lex *lx, const char *prefix, struct tg_names *all,
                         struct tg_names *branches)
{
    char macro[64];
    for (size_t pos = 0; pos < lx->len; pos++) {
        if (pos && lx->code[pos - 1u] != '\n')
            continue;
        const char *lit;
        size_t ll;
        if (!row_literal(lx->code, lx->len, pos, prefix, macro, sizeof macro, &lit, &ll))
            continue;
        if (!tg_names_add(all, lit, ll))
            return false;
        if (branches && strcmp(macro, "ZCL_COMMAND_BRANCH") == 0 && !tg_names_add(branches, lit, ll))
            return false;
    }
    return true;
}

static bool collect_groups(const struct tg_lex *lx, struct tg_names *groups)
{
    static const char *const heads[] = {"ZCL_TEST_GROUP(", "ZCL_SPEC_GROUP("};
    for (size_t pos = 0; pos < lx->len; pos++) {
        if (pos && lx->code[pos - 1u] != '\n')
            continue;
        for (size_t h = 0; h < 2; h++) {
            size_t hl = strlen(heads[h]);
            if (pos + hl > lx->len || memcmp(lx->code + pos, heads[h], hl) != 0)
                continue;
            size_t k = pos + hl;
            while (k < lx->len && is_idc((unsigned char)lx->code[k]))
                k++;
            if (!tg_names_add(groups, lx->code + pos + hl, k - pos - hl))
                return false;
        }
    }
    return true;
}

static bool collect_handlers(const struct tg_lex *lx, struct tg_names *handlers)
{
    size_t pl = strlen(HANDLER_PREFIX);
    for (size_t pos = 0; pos < lx->len;) {
        if (!is_idc((unsigned char)lx->masked[pos])) {
            pos++;
            continue;
        }
        size_t k = pos;
        while (k < lx->len && is_idc((unsigned char)lx->masked[k]))
            k++;
        if (k - pos > pl && memcmp(lx->masked + pos, HANDLER_PREFIX, pl) == 0 &&
            !tg_names_add(handlers, lx->masked + pos, k - pos))
            return false;
        pos = k;
    }
    return true;
}

static bool scan_file(const char *root, const char *rel, struct tg_world *w, struct tg_err *e,
                      bool (*fn)(const struct tg_lex *, struct tg_world *))
{
    struct tg_sb text = {0};
    struct tg_lex lx;
    if (!read_authored(root, rel, &text, e)) {
        tg_sb_free(&text);
        return false;
    }
    if (!tg_lex_run(text.p ? text.p : "", text.n, &lx)) {
        tg_sb_free(&text);
        return tg_fail(e, "IO_ERROR", "out of memory scanning %s", rel);
    }
    bool ok = fn(&lx, w);
    tg_lex_free(&lx);
    tg_sb_free(&text);
    return ok || tg_fail(e, "IO_ERROR", "out of memory scanning %s", rel);
}

static bool fn_def(const struct tg_lex *lx, struct tg_world *w)
{
    return collect_rows(lx, "ZCL_COMMAND_", &w->paths, &w->branches) &&
           collect_handlers(lx, &w->handlers);
}

static bool fn_header(const struct tg_lex *lx, struct tg_world *w)
{
    return collect_handlers(lx, &w->handlers);
}

static bool fn_remote(const struct tg_lex *lx, struct tg_world *w)
{
    return collect_rows(lx, "REMOTE_COMMAND_CLASS", &w->remote, NULL);
}

static bool fn_groups(const struct tg_lex *lx, struct tg_world *w)
{
    return collect_groups(lx, &w->groups);
}

/* Sorted entry names of one directory, dot files excluded. */
static bool list_dir(const char *root, const char *rel, struct tg_names *out, struct tg_err *e)
{
    char path[1024];
    if (!tg_join(path, sizeof path, root, rel))
        return tg_fail(e, "IO_ERROR", "path too long: %s", rel);
    DIR *d = opendir(path);
    if (!d)
        return tg_fail(e, "IO_ERROR", "cannot list %s", rel);
    struct dirent *de;
    bool ok = true;
    bool long_name = false;
    while (ok && !long_name && (de = readdir(d)) != NULL) {
        long_name = strlen(de->d_name) > 200u;
        if (de->d_name[0] != '.' && !long_name)
            ok = tg_names_add(out, de->d_name, strlen(de->d_name));
    }
    closedir(d);
    if (long_name)
        return tg_fail(e, "SOURCE_NAME_BAD", "%s holds a name longer than 200 bytes", rel);
    if (!ok)
        return tg_fail(e, "IO_ERROR", "out of memory listing %s", rel);
    tg_names_sort(out);
    return true;
}

static bool ends_with(const char *s, const char *suffix)
{
    size_t n = strlen(s);
    size_t k = strlen(suffix);
    return n >= k && strcmp(s + n - k, suffix) == 0;
}

static bool scan_dir(const char *root, const char *rel, const char *suffix, struct tg_world *w,
                     struct tg_err *e, bool (*fn)(const struct tg_lex *, struct tg_world *),
                     int depth)
{
    struct tg_names names = {0};
    bool ok = list_dir(root, rel, &names, e);
    for (size_t i = 0; ok && i < names.n; i++) {
        char child[512], full[1024];
        struct stat st;
        if (!tg_join(child, sizeof child, rel, names.v[i]) ||
            !tg_join(full, sizeof full, root, child) || lstat(full, &st) != 0) {
            ok = tg_fail(e, "IO_ERROR", "cannot stat %s/%s", rel, names.v[i]);
        } else if (S_ISDIR(st.st_mode) && depth < 4) {
            ok = scan_dir(root, child, suffix, w, e, fn, depth + 1);
        } else if (ends_with(names.v[i], suffix)) {
            ok = scan_file(root, child, w, e, fn);
        }
    }
    tg_names_free(&names);
    return ok;
}

bool tg_world_load(const char *root, struct tg_world *w, struct tg_err *e)
{
    *w = (struct tg_world){0};
    struct tg_target t[TG_MAX_TARGETS];
    size_t n = tg_targets(t, TG_MAX_TARGETS);
    bool ok = scan_dir(root, DEF_DIR, ".def", w, e, fn_def, 0) &&
              scan_dir(root, HEADER_DIR, ".h", w, e, fn_header, 0);
    ok = ok && scan_file(root, tg_remote_path, w, e, fn_remote);
    for (size_t i = 0; ok && i < n; i++) {
        if (t[i].kind == TGT_CATALOG)
            ok = scan_file(root, t[i].path, w, e, fn_groups);
    }
    if (!ok)
        tg_world_free(w);
    return ok;
}
