/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Path canonicalization, file table and search directories shared by both semantic manifest producers. */
/* realpath() is declared only under _DEFAULT_SOURCE on glibc without the
 * fortify inline; set it before the first header pulls in <features.h>. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "clang_manifest_core.h"

#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* ---- lexical normalization ----------------------------------------------- */

/* Collapse "//", "." and ".." of an absolute path in place ("/.." is "/"). */
static void cm_lexical(char *p)
{
    char *out = p;
    size_t n = strlen(p);
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && p[j] != '/')
            j++;
        size_t len = j - i;
        if (len == 0 || (len == 1 && p[i] == '.')) {
            /* skip */
        } else if (len == 2 && p[i] == '.' && p[i + 1] == '.') {
            while (out > p && *(out - 1) != '/')
                out--;
            if (out > p)
                out--;
        } else {
            *out++ = '/';
            memmove(out, p + i, len);
            out += len;
        }
        i = j + 1;
    }
    if (out == p)
        *out++ = '/';
    *out = '\0';
}

bool cm_absolute(struct cm_core *c, const char *path, char out[PATH_MAX])
{
    char joined[PATH_MAX * 2];
    int w = path[0] == '/'
                ? snprintf(joined, sizeof(joined), "%s", path)
                : snprintf(joined, sizeof(joined), "%s/%s", c->root, path);
    if (w < 0 || (size_t)w >= sizeof(joined) || (size_t)w >= PATH_MAX)
        return cm_fail(c, "path too long: %s", path);
    if (realpath(joined, out) != NULL)
        return true;
    memcpy(out, joined, (size_t)w + 1);
    cm_lexical(out);
    return true;
}

static bool cm_under(const char *p, const char *dir, size_t dir_len)
{
    return dir_len > 0 && strncmp(p, dir, dir_len) == 0 &&
           (p[dir_len] == '\0' || p[dir_len] == '/');
}

static bool cm_host_resource_path(const struct cm_core *c, const char *abs)
{
    if (!cm_under(abs, c->host_resource_root, c->host_resource_root_len))
        return false;
    const char *rest = abs + c->host_resource_root_len;
    return rest[0] == '\0' ||
        (strncmp(rest, "/include", 8) == 0 &&
         (rest[8] == '\0' || rest[8] == '/'));
}

/* Canonical spelling of an absolute path: repo-relative, "." for the root,
 * or "@sys/..." for the system. A host path under $HOME but outside the
 * checkout has no host-independent spelling and is refused. */
static bool cm_spell(struct cm_core *c, const char *abs, const char *root_tok,
                     char **out)
{
    char buf[PATH_MAX + 16];
    if (cm_under(abs, c->root, c->root_len)) {
        const char *rest = abs + c->root_len;
        if (root_tok != NULL)
            (void)snprintf(buf, sizeof(buf), "%s%s", root_tok, rest);
        else
            (void)snprintf(buf, sizeof(buf), "%s", *rest ? rest + 1 : ".");
    } else if (cm_host_resource_path(c, abs)) {
        /* abs has already passed realpath normalization. A symlink out of
         * the selected include tree cannot acquire this virtual spelling.
         * FILES still hashes the exact bytes and IDENTITY binds the compiler. */
        int n = snprintf(buf, sizeof(buf), "@sys/clang-resource%s",
                         abs + c->host_resource_root_len);
        if (n < 0 || (size_t)n >= sizeof(buf))
            return cm_fail(c, "compiler resource path too long");
    } else if (cm_under(abs, c->home, c->home_len)) {
        return cm_fail(c, "refusing host path outside the checkout: %s", abs);
    } else {
        /* Reserve the virtual resource namespace: an ordinary host path
         * must not alias the build-selected headers in FILES or IDENTITY. */
        if (c->host_resource_root_len &&
            cm_under(abs, "/clang-resource", sizeof("/clang-resource") - 1))
            return cm_fail(c, "host path collides with compiler resource namespace: %s", abs);
        (void)snprintf(buf, sizeof(buf), "@sys%s", strcmp(abs, "/") ? abs : "");
    }
    *out = cm_strdup(buf);
    return *out != NULL || cm_fail(c, "out of memory");
}

bool cm_spell_real(struct cm_core *c, const char *abs, char **out)
{
    return cm_spell(c, abs, NULL, out);
}

bool cm_norm_path(struct cm_core *c, const char *path, char **out)
{
    char abs[PATH_MAX];
    return cm_absolute(c, path, abs) && cm_spell(c, abs, NULL, out);
}

/* ---- argv ------------------------------------------------------------------ */

static bool cm_virtual(const char *s)
{
    static const char *const v[] = {"/zclassic23", "/zbuild"};
    for (size_t k = 0; k < sizeof(v) / sizeof(v[0]); k++) {
        size_t n = strlen(v[k]);
        if (strncmp(s, v[k], n) == 0 && memchr("/=:,;", s[n], 6) != NULL)
            return true;
    }
    return false;
}

/* Rewrite every absolute path that starts at a path boundary: the checkout
 * becomes "@root", a virtual root stays, anything else becomes "@sys/...". */
bool cm_norm_arg(struct cm_core *c, const char *arg, char **out)
{
    char buf[PATH_MAX * 4];
    size_t w = 0, n = strlen(arg);
    for (size_t i = 0; i < n;) {
        size_t end = i;
        char tok[PATH_MAX], abs[PATH_MAX], *spelled;
        if (arg[i] != '/' || !vcs_semantic_argv_path_boundary_v1(arg, i) ||
            cm_virtual(arg + i)) {
            if (w + 1 >= sizeof(buf))
                return cm_fail(c, "argument too long");
            buf[w++] = arg[i++];
            continue;
        }
        while (end < n && memchr("=,:;", arg[end], 4) == NULL)
            end++;
        if (end - i >= sizeof(tok))
            return cm_fail(c, "path in argument too long");
        memcpy(tok, arg + i, end - i);
        tok[end - i] = '\0';
        if (!cm_absolute(c, tok, abs) || !cm_spell(c, abs, "@root", &spelled))
            return false;
        if (w + strlen(spelled) >= sizeof(buf))
            return cm_fail(c, "argument too long");
        memcpy(buf + w, spelled, strlen(spelled));
        w += strlen(spelled);
        free(spelled);
        i = end;
    }
    buf[w] = '\0';
    *out = cm_strdup(buf);
    return *out != NULL || cm_fail(c, "out of memory");
}

/* ---- file table -------------------------------------------------------------- */

bool cm_file_add(struct cm_core *c, const void *key, const char *real,
                 const char *opened, bool is_main, const char *contents,
                 size_t size)
{
    struct cm_file *e;
    if (!cm_grow((void **)&c->files, &c->capfiles, c->nfiles, sizeof(*c->files)))
        return cm_fail(c, "out of memory");
    e = &c->files[c->nfiles];
    *e = (struct cm_file){.key = key, .contents = contents, .size = size};
    e->real = cm_strdup(real);
    e->opened = cm_strdup(opened);
    if (e->real == NULL || e->opened == NULL || !cm_spell(c, e->real, NULL, &e->path)) {
        free(e->real);
        free(e->opened);
        return cm_fail(c, "cannot record file %s", real);
    }
    if (contents == NULL)
        return cm_fail(c, "no contents for %s", e->path);
    if (is_main)
        e->origin = VCS_SEMANTIC_ORIGIN_V1_MAIN;
    else
        e->origin = e->path[0] == '@' ? VCS_SEMANTIC_ORIGIN_V1_SYSTEM
                                      : VCS_SEMANTIC_ORIGIN_V1_REPO;
    c->nfiles++;
    return true;
}

const struct cm_file *cm_file_by_key(struct cm_core *c, const void *key)
{
    if (key == NULL)
        return NULL;
    if (c->file_hint < c->nfiles && c->files[c->file_hint].key == key)
        return &c->files[c->file_hint];
    for (size_t k = 0; k < c->nfiles; k++) {
        if (c->files[k].key == key) {
            c->file_hint = k;
            return &c->files[k];
        }
    }
    return NULL;
}

bool cm_emit_files(struct cm_core *c)
{
    struct vcs_semantic_record_v1 rec = {0};
    for (size_t k = 0; k < c->nfiles; k++) {
        const struct cm_file *e = &c->files[k];
        uint8_t digest[32];
        zcl_sha3_256((const unsigned char *)e->contents, e->size, digest);
        vcs_semantic_record_v1_reset(&rec);
        vcs_semantic_record_v1_cstr(&rec, e->path);
        vcs_semantic_record_v1_digest(&rec, digest);
        vcs_semantic_record_v1_u8(&rec, e->origin);
        if (!cm_add(c, VCS_SEMANTIC_SECTION_V1_FILES, &rec)) {
            vcs_semantic_record_v1_free(&rec);
            return false;
        }
    }
    vcs_semantic_record_v1_free(&rec);
    return true;
}

/* ---- search directories ------------------------------------------------------ */

bool cm_push_dir(struct cm_core *c, struct cm_dirs *d, const char *raw,
                 size_t len)
{
    struct cm_dir *e;
    if (!cm_grow((void **)&d->items, &d->cap, d->n, sizeof(*d->items)))
        return cm_fail(c, "out of memory");
    e = &d->items[d->n];
    *e = (struct cm_dir){0};
    e->raw = cm_strndup(raw, len);
    if (e->raw == NULL)
        return cm_fail(c, "out of memory");
    if (!cm_norm_path(c, e->raw, &e->path)) {
        free(e->raw);
        return false;
    }
    d->n++;
    return true;
}

void cm_find_resource_dir(struct cm_core *c)
{
    for (size_t k = 0; k < c->angled.n; k++) {
        char probe[PATH_MAX + 32];
        struct stat sb;
        if (c->angled.items[k].path[0] != '@')
            continue;
        (void)snprintf(probe, sizeof(probe), "%s/__stddef_max_align_t.h",
                       c->angled.items[k].raw);
        if (stat(probe, &sb) == 0 && S_ISREG(sb.st_mode)) {
            c->resource_dir = c->angled.items[k].path;
            return;
        }
    }
}
