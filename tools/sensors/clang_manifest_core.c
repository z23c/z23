/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared producer core: lifecycle, helpers, argv identity and manifest finish for both semantic manifest producers. */
/* realpath() is declared only under _DEFAULT_SOURCE on glibc without the
 * fortify inline; set it before the first header pulls in <features.h>. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "clang_manifest_core.h"

#include "base/hex.h"
#include "base/safe_alloc.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *const k_cm_env[] = {VCS_SEMANTIC_ENV_V1_ALLOWLIST};

bool cm_fail(struct cm_core *c, const char *fmt, ...)
{
    va_list ap;
    if (c->failed)
        return false;
    c->failed = true;
    va_start(ap, fmt);
    (void)vsnprintf(c->why, sizeof(c->why), fmt, ap);
    va_end(ap);
    return false;
}

bool cm_grow(void **items, size_t *cap, size_t n, size_t elem)
{
    size_t next;
    void *grown;
    if (n < *cap)
        return true;
    next = *cap ? *cap * 2 : 16;
    if (next > SIZE_MAX / elem)
        return false;
    grown = zcl_realloc(*items, next * elem, "clang_manifest.grow");
    if (grown == NULL)
        return false;
    *items = grown;
    *cap = next;
    return true;
}

char *cm_strndup(const char *s, size_t n)
{
    char *out = zcl_malloc(n + 1, "clang_manifest.str");
    if (out != NULL) {
        if (n > 0)
            memcpy(out, s, n);
        out[n] = '\0';
    }
    return out;
}

char *cm_strdup(const char *s)
{
    return cm_strndup(s, strlen(s));
}

bool cm_add(struct cm_core *c, enum vcs_semantic_section_v1 section,
            struct vcs_semantic_record_v1 *rec)
{
    if (rec->failed || !vcs_semantic_builder_v1_add(c->b, section, rec))
        return cm_fail(c, "cannot add a %s record",
                       vcs_semantic_section_v1_name(section));
    return true;
}

void cm_hex(const uint8_t d[32], char out[65])
{
    zcl_hex_encode(d, 32, out);
}

bool cm_read_file(const char *path, uint8_t **out, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    long size;
    bool ok = false;
    *out = NULL;
    if (fp == NULL)
        return false;
    if (fseek(fp, 0, SEEK_END) == 0 && (size = ftell(fp)) >= 0 &&
        fseek(fp, 0, SEEK_SET) == 0) {
        *out = zcl_malloc((size_t)size + 1, "clang_manifest.read");
        ok = *out != NULL && fread(*out, 1, (size_t)size, fp) == (size_t)size;
        *len = (size_t)size;
    }
    (void)fclose(fp);
    if (ok)
        (*out)[*len] = 0;
    return ok;
}

bool cm_core_init(struct cm_core *c, const char *root)
{
    const char *home = getenv("HOME");
    if (realpath(root, c->root) == NULL || chdir(c->root) != 0)
        return cm_fail(c, "cannot enter root %s", root);
    c->root_len = strlen(c->root);
    /* cm_spell refuses a host path under the home directory; with no
     * resolved home it would spell such a path @sys/<abs> and write the
     * host's user name into the manifest. Refuse before any artifact. */
    if (home == NULL || home[0] != '/' || realpath(home, c->home) == NULL)
        return cm_fail(c, "home directory unresolved: cannot guard host-path "
                          "leakage (HOME %s)",
                       home == NULL ? "unset"
                                    : home[0] != '/' ? "not absolute"
                                                     : "does not resolve");
    c->home_len = strlen(c->home);
    c->host_resource_root_len = 0;
#if defined(CM_HOST_RESOURCE_DIR)
    struct stat resource_stat;
    if (realpath(CM_HOST_RESOURCE_DIR, c->host_resource_root) == NULL ||
        strcmp(c->host_resource_root, "/") == 0 ||
        stat(c->host_resource_root, &resource_stat) != 0 ||
        !S_ISDIR(resource_stat.st_mode))
        return cm_fail(c, "build-selected compiler resource directory does not resolve");
    c->host_resource_root_len = strlen(c->host_resource_root);
#endif
    c->b = vcs_semantic_builder_v1_new();
    return c->b != NULL || cm_fail(c, "cannot create the manifest builder");
}

static void cm_free_dirs(struct cm_dirs *d)
{
    for (size_t k = 0; k < d->n; k++) {
        free(d->items[k].raw);
        free(d->items[k].path);
    }
    free(d->items);
}

void cm_core_free(struct cm_core *c)
{
    for (size_t k = 0; k < c->nfiles; k++) {
        free(c->files[k].path);
        free(c->files[k].real);
        free(c->files[k].opened);
        free(c->files[k].live);
    }
    free(c->files);
    cm_free_dirs(&c->quote);
    cm_free_dirs(&c->angled);
    cm_free_dirs(&c->ignored);
    for (size_t k = 0; k < c->nmacros; k++) {
        free(c->macros[k].name);
        free(c->macros[k].body);
    }
    free(c->macros);
    for (size_t k = 0; k < c->nexps; k++) {
        free(c->exps[k].name);
        free(c->exps[k].def_id);
    }
    free(c->exps);
    for (size_t k = 0; k < c->nfns; k++) {
        struct cm_function *fn = &c->fns[k];
        for (size_t j = 0; j < fn->ncallees; j++)
            free(fn->callees[j]);
        free(fn->callees);
        free(fn->name);
        free(fn->type);
        free(fn->id);
    }
    free(c->fns);
    for (size_t k = 0; k < c->nasserts; k++)
        free(c->asserts[k].site);
    free(c->asserts);
    free(c->entries);
    for (size_t k = 0; k < c->nocc; k++) {
        free(c->occ[k].site);
        free(c->occ[k].detail);
    }
    free(c->occ);
    free(c->paste_piece);
    vcs_semantic_namespace_v1_free(c->ns);
    vcs_semantic_builder_v1_free(c->b);
    memset(c, 0, sizeof(*c));
}

/* ---- argv ------------------------------------------------------------------- */

/* Output-only controls never enter the identity or the parse. */
int cm_output_arg(const char *a)
{
    static const char *const bare[] = {"-c", "-MD", "-MMD", "-MP", "-fsyntax-only"};
    static const char *const with_value[] = {"-o", "-MF", "-MT", "-MQ"};
    for (size_t k = 0; k < sizeof(bare) / sizeof(bare[0]); k++) {
        if (strcmp(a, bare[k]) == 0)
            return 1;
    }
    for (size_t k = 0; k < sizeof(with_value) / sizeof(with_value[0]); k++) {
        size_t n = strlen(with_value[k]);
        if (strcmp(a, with_value[k]) == 0)
            return 2;
        if (strncmp(a, with_value[k], n) == 0)
            return 1;
    }
    return 0;
}

/* ---- identity ---------------------------------------------------------------- */

static void cm_dir_list(struct vcs_semantic_record_v1 *rec,
                        const struct cm_dirs *d)
{
    vcs_semantic_record_v1_u32(rec, (uint32_t)d->n);
    for (size_t k = 0; k < d->n; k++)
        vcs_semantic_record_v1_cstr(rec, d->items[k].path);
}

static bool cm_env_list(struct cm_core *c, struct vcs_semantic_record_v1 *rec)
{
    size_t n = sizeof(k_cm_env) / sizeof(k_cm_env[0]);
    vcs_semantic_record_v1_u32(rec, (uint32_t)n);
    for (size_t k = 0; k < n; k++) {
        const char *v = getenv(k_cm_env[k]);
        char *norm = NULL;
        vcs_semantic_record_v1_cstr(rec, k_cm_env[k]);
        vcs_semantic_record_v1_u8(rec, v != NULL ? 1 : 0);
        if (v != NULL && !cm_norm_arg(c, v, &norm))
            return false;
        vcs_semantic_record_v1_cstr(rec, norm != NULL ? norm : "");
        free(norm);
    }
    return true;
}

/* The front end names only itself; the object is built by another compiler
 * (or another version of this one), whose code generation the facts must
 * not be assumed to match. cm_object_cc_text (clang_manifest_cc.c) names
 * it, so any compiler change is IDENTITY drift. */
static char *cm_compiler_text(struct cm_core *c, const char *front_end)
{
    char *object_cc = cm_object_cc_text(c), *out;
    size_t n;
    if (object_cc == NULL)
        return NULL;
    n = strlen(front_end) + strlen(object_cc) + 3;
    out = zcl_malloc(n, "clang_manifest.compiler");
    if (out != NULL)
        (void)snprintf(out, n, "%s; %s", front_end, object_cc);
    else
        (void)cm_fail(c, "out of memory");
    free(object_cc);
    return out;
}

bool cm_emit_identity(struct cm_core *c, const struct cm_identity *id)
{
    struct vcs_semantic_record_v1 rec = {0};
    char *compiler = cm_compiler_text(c, id->compiler);
    bool ok;
    if (compiler == NULL)
        return false;
    vcs_semantic_record_v1_cstr(&rec, compiler);
    free(compiler);
    vcs_semantic_record_v1_cstr(&rec, c->resource_dir);
    vcs_semantic_record_v1_cstr(&rec, id->triple);
    vcs_semantic_record_v1_cstr(&rec, id->main_path);
    vcs_semantic_record_v1_u32(&rec, (uint32_t)id->argc);
    for (size_t k = 0; k < id->argc; k++)
        vcs_semantic_record_v1_cstr(&rec, id->argv[k]);
    cm_dir_list(&rec, &c->quote);
    cm_dir_list(&rec, &c->angled);
    cm_dir_list(&rec, &c->ignored);
    ok = cm_env_list(c, &rec) &&
         cm_add(c, VCS_SEMANTIC_SECTION_V1_IDENTITY, &rec);
    vcs_semantic_record_v1_free(&rec);
    return ok;
}

/* ---- finish -------------------------------------------------------------------- */

bool cm_write_file(const char *path, const uint8_t *b, size_t n)
{
    char tmp[PATH_MAX + 32];
    FILE *fp;
    bool ok;
    (void)snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
    fp = fopen(tmp, "wb");
    ok = fp != NULL && fwrite(b, 1, n, fp) == n;
    if (fp != NULL && fclose(fp) != 0)
        ok = false;
    ok = ok && rename(tmp, path) == 0;
    if (!ok)
        (void)unlink(tmp);
    return ok;
}

bool cm_finish_bytes(struct cm_core *c, uint8_t **bytes, size_t *len)
{
    *bytes = NULL;
    *len = 0;
    if (c->failed)
        return false;
    if (vcs_semantic_builder_v1_finish(c->b, bytes, len, c->why,
                                       sizeof(c->why)))
        return true;
    c->failed = true;
    free(*bytes);
    *bytes = NULL;
    return false;
}

bool cm_stream_sha3(FILE *fp, uint8_t out[32])
{
    struct sha3_256_ctx h;
    unsigned char buf[65536];
    size_t n;
    bool ok;
    if (fp == NULL)
        return false;
    sha3_256_init(&h);
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        sha3_256_write(&h, buf, n);
    ok = ferror(fp) == 0;
    (void)fclose(fp);
    sha3_256_finalize(&h, out);
    return ok;
}
