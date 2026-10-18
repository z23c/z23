/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: install, switch, rollback and list for the signed plugin store. */

#include "plugin_internal.h"
#if defined(_WIN32)
#include "platform/directory_transaction.h"
#include "platform/directory_compat.h"
#include <io.h>
#endif

#include "base/safe_alloc.h"
#include "platform/atomic_link.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PS_KEYS_FILE "publisher_keys"
#define PS_MANIFEST_SUFFIX ".plugin.json"

struct ps_paths {
    char manifest[PLUGIN_PATH_MAX];
    char sig[PLUGIN_PATH_MAX];
    char exe[PLUGIN_PATH_MAX];
};

const char *plugin_slot_state_name(enum plugin_slot_state state)
{
    switch (state) {
    case PLUGIN_SLOT_OK:
        return "ok";
    case PLUGIN_SLOT_MISSING:
        return "missing";
    case PLUGIN_SLOT_UNREADABLE:
        return "unreadable";
    case PLUGIN_SLOT_CORRUPT:
        return "corrupt";
    }
    return "corrupt";
}

#ifdef ZCL_TESTING
static char g_ps_fail_suffix[PLUGIN_PATH_MAX];
static unsigned g_ps_fail_after;
static bool g_ps_fail_armed;

void plugin_store_test_fail_readdir(const char *suffix, unsigned after)
{
    g_ps_fail_armed = suffix != NULL;
    g_ps_fail_after = after;
    snprintf(g_ps_fail_suffix, sizeof(g_ps_fail_suffix), "%s", suffix ? suffix : "");
}

static bool ps_seam_fails(const char *path)
{
    size_t n = strlen(path), m = strlen(g_ps_fail_suffix);
    if (!g_ps_fail_armed || m > n || strcmp(path + n - m, g_ps_fail_suffix) != 0)
        return false;
    if (g_ps_fail_after > 0) {
        g_ps_fail_after--;
        return false;
    }
    return true;
}
#endif

/* readdir that reports the end of the directory (NULL, errno 0) apart from a
 * failed read (NULL, errno set). */
static struct dirent *ps_readdir(DIR *d, const char *path)
{
#ifdef ZCL_TESTING
    if (ps_seam_fails(path)) {
        errno = EIO;
        return NULL;
    }
#else
    (void)path;
#endif
    errno = 0;
    return readdir(d);
}

static bool ps_is_dir(const char *path)
{
#if defined(_WIN32)
    return plugin_check_dir(path) == PLUGIN_OK;
#else

    struct stat st;
    return lstat(path, &st) == 0 && S_ISDIR(st.st_mode);

#endif
}

static enum plugin_status ps_read_error(enum plugin_status missing,
                                        enum plugin_status oversize)
{
    if (errno == ENOENT)
        return missing;
    if (errno == EFBIG)
        return oversize;
    return errno == EPERM || errno == ELOOP ? PLUGIN_ERR_KEYS_INSECURE
                                            : PLUGIN_ERR_IO;
}

/* Verify one manifest, signature and executable set end to end. */
static enum plugin_status ps_verify_set(const struct ps_paths *p,
                                        const char *keys_file, const char *keys_bytes,
                                        size_t keys_len, unsigned flags,
                                        struct plugin_manifest *out)
{
    char *mf = NULL, *sg = NULL;
    size_t mf_len = 0, sg_len = 0;
    char hex[PLUGIN_HEX_SHA3_512 + 1];
    if (!plugin_read_file(p->manifest, PLUGIN_FILE_MAX, flags, &mf, &mf_len))
        return ps_read_error(PLUGIN_ERR_MANIFEST_MISSING,
                             PLUGIN_ERR_MANIFEST_INVALID);
    enum plugin_status st = PLUGIN_OK;
    if (!plugin_read_file(p->sig, PLUGIN_FILE_MAX, flags, &sg, &sg_len))
        st = ps_read_error(PLUGIN_ERR_SIG_MISSING, PLUGIN_ERR_SIG_INVALID);
    if (st == PLUGIN_OK)
        st = keys_bytes
                 ? plugin_verify_manifest_keys(mf, mf_len, sg, sg_len, keys_bytes,
                                                keys_len, out)
                 : plugin_verify_manifest(mf, mf_len, sg, sg_len, keys_file, out);
    if (st == PLUGIN_OK)
        st = plugin_hash_path(p->exe, flags, hex);
    if (st == PLUGIN_OK && strcmp(hex, out->exe_sha3) != 0)
        st = PLUGIN_ERR_EXE_HASH;
    free(mf);
    free(sg);
    return st;
}

static bool ps_keys_path(const char *root, char *out, size_t cap)
{
    return plugin_join(out, cap, root, PS_KEYS_FILE, NULL, NULL);
}

static bool ps_generation_paths(const char *root, const char *name,
                                const char *generation, struct ps_paths *p)
{
    char dir[PLUGIN_PATH_MAX], leaf[PLUGIN_NAME_MAX + 16];
    if (!plugin_join(dir, sizeof(dir), root, name, "generations", generation))
        return false;
    snprintf(leaf, sizeof(leaf), "%s.plugin.json", name);
    if (!plugin_join(p->manifest, sizeof(p->manifest), dir, leaf, NULL, NULL))
        return false;
    snprintf(leaf, sizeof(leaf), "%s.plugin.sig", name);
    return plugin_join(p->sig, sizeof(p->sig), dir, leaf, NULL, NULL) &&
           plugin_join(p->exe, sizeof(p->exe), dir, name, NULL, NULL);
}

/* The store root, the plugin directory and its generations directory must
 * each be a real directory owned by the user and closed to group and others. */
static enum plugin_status ps_check_chain(const char *root, const char *plugdir)
{
    char gens[PLUGIN_PATH_MAX];
    enum plugin_status st = plugin_check_dir(root);
    if (st == PLUGIN_OK)
        st = plugin_check_dir(plugdir);
    if (st == PLUGIN_OK &&
        !plugin_join(gens, sizeof(gens), plugdir, "generations", NULL, NULL))
        st = PLUGIN_ERR_ARGUMENT;
    if (st == PLUGIN_OK) {
        st = plugin_check_dir(gens);
        if (st == PLUGIN_ERR_NOT_INSTALLED)
            st = PLUGIN_ERR_NO_GENERATION;
    }
    return st;
}

enum plugin_status plugin_check_generation_dirs(const char *root, const char *name,
                                                const char *generation)
{
    char dir[PLUGIN_PATH_MAX], gen_dir[PLUGIN_PATH_MAX];
    if (!plugin_name_valid(name) ||
        !plugin_hex_valid(generation, PLUGIN_HEX_SHA3_512) ||
        !plugin_join(dir, sizeof(dir), root, name, NULL, NULL) ||
        !plugin_join(gen_dir, sizeof(gen_dir), dir, "generations", generation, NULL))
        return PLUGIN_ERR_ARGUMENT;
    enum plugin_status st = ps_check_chain(root, dir);
    if (st != PLUGIN_OK)
        return st;
    st = plugin_check_dir(gen_dir);
    return st == PLUGIN_ERR_NOT_INSTALLED ? PLUGIN_ERR_NO_GENERATION : st;
}

/* Keys come from the file at keys_file, or from keys_bytes when given. */
static enum plugin_status ps_verify_generation(const char *root, const char *name,
                                               const char *generation, const char *keys_file,
                                               const char *keys_bytes, size_t keys_len,
                                               struct plugin_manifest *out)
{
    struct ps_paths p;
    if (!ps_generation_paths(root, name, generation, &p))
        return PLUGIN_ERR_ARGUMENT;
    enum plugin_status st = plugin_check_generation_dirs(root, name, generation);
    if (st != PLUGIN_OK)
        return st;
    st = ps_verify_set(&p, keys_file, keys_bytes, keys_len, PLUGIN_OPEN_NOFOLLOW, out);
    if (st == PLUGIN_OK &&
        (strcmp(out->name, name) != 0 ||
         (strcmp(out->generation, generation) != 0 &&
          /* generations stored before the id covered the manifest */
          strcmp(out->exe_sha3, generation) != 0)))
        st = PLUGIN_ERR_MANIFEST_INVALID;
    return st;
}

enum plugin_status plugin_verify_generation_manifest(const char *root,
                                                     const char *name,
                                                     const char *generation,
                                                     struct plugin_manifest *out)
{
    char keys_file[PLUGIN_PATH_MAX];
    if (!ps_keys_path(root, keys_file, sizeof(keys_file)))
        return PLUGIN_ERR_ARGUMENT;
    return ps_verify_generation(root, name, generation, keys_file, NULL, 0, out);
}

enum plugin_status plugin_verify_generation_manifest_keys(const char *root,
                                                           const char *name,
                                                           const char *generation,
                                                           const char *keys,
                                                           size_t keys_len,
                                                           struct plugin_manifest *out)
{
    return ps_verify_generation(root, name, generation, NULL, keys, keys_len, out);
}

enum plugin_status plugin_verify_generation(const char *root, const char *name,
                                            const char *generation)
{
    struct plugin_manifest m;
    return plugin_verify_generation_manifest(root, name, generation, &m);
}

/* Derive sibling signature and executable paths from NAME.plugin.json. */
static enum plugin_status ps_source_paths(const char *manifest_path,
                                          char stem[PLUGIN_NAME_MAX + 1],
                                          struct ps_paths *p)
{
    size_t len = manifest_path ? strlen(manifest_path) : 0;
    size_t suffix = sizeof(PS_MANIFEST_SUFFIX) - 1;
    if (len <= suffix || len >= PLUGIN_PATH_MAX ||
        strcmp(manifest_path + len - suffix, PS_MANIFEST_SUFFIX) != 0)
        return PLUGIN_ERR_ARGUMENT;
    const char *slash = strrchr(manifest_path, '/');
    const char *base = slash ? slash + 1 : manifest_path;
    size_t stem_len = (size_t)(manifest_path + len - suffix - base);
    if (stem_len < 1 || stem_len > PLUGIN_NAME_MAX)
        return PLUGIN_ERR_ARGUMENT;
    memcpy(stem, base, stem_len);
    stem[stem_len] = '\0';
    if (!plugin_name_valid(stem))
        return PLUGIN_ERR_ARGUMENT;
    size_t dir_len = (size_t)(base - manifest_path);
    int a = snprintf(p->manifest, sizeof(p->manifest), "%s", manifest_path);
    int b = snprintf(p->sig, sizeof(p->sig), "%.*s%s.plugin.sig",
                     (int)dir_len, manifest_path, stem);
    int c = snprintf(p->exe, sizeof(p->exe), "%.*s%s", (int)dir_len,
                     manifest_path, stem);
    return a > 0 && b > 0 && c > 0 && (size_t)b < sizeof(p->sig) &&
                   (size_t)c < sizeof(p->exe)
               ? PLUGIN_OK : PLUGIN_ERR_ARGUMENT;
}

/* Copy the verified set into a staging directory and verify the copy. */
static enum plugin_status ps_stage(const struct ps_paths *src, const char *name,
                                   const char *staging, const char *keys_file,
                                   struct plugin_manifest *m)
{
    struct ps_paths dst;
    char leaf[PLUGIN_NAME_MAX + 16], hex[PLUGIN_HEX_SHA3_512 + 1];
    snprintf(leaf, sizeof(leaf), "%s.plugin.json", name);
    bool ok = plugin_join(dst.manifest, sizeof(dst.manifest), staging, leaf, NULL, NULL);
    snprintf(leaf, sizeof(leaf), "%s.plugin.sig", name);
    ok = ok && plugin_join(dst.sig, sizeof(dst.sig), staging, leaf, NULL, NULL) &&
         plugin_join(dst.exe, sizeof(dst.exe), staging, name, NULL, NULL);
    if (!ok)
        return PLUGIN_ERR_ARGUMENT;
    enum plugin_status st = plugin_copy_file(src->exe, dst.exe, 0555, hex);
    if (st == PLUGIN_OK)
        st = plugin_copy_file(src->manifest, dst.manifest, 0444, hex);
    if (st == PLUGIN_OK)
        st = plugin_copy_file(src->sig, dst.sig, 0444, hex);
    return st == PLUGIN_OK ? ps_verify_set(&dst, keys_file, NULL, 0, PLUGIN_OPEN_NOFOLLOW, m)
                           : st;
}

/* Move a failed generation aside and publish its verified staging copy.
 * A definitive publication failure attempts restoration; an unknown outcome
 * retains the involved objects for reconciliation. */
#if defined(_WIN32)
struct ps_windows_replacement {
    struct platform_directory_transaction from, to, staged, prior;
    char source[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    char target[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    char aside[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    bool had;
};

static void ps_windows_replacement_init(struct ps_windows_replacement *state)
{
    platform_directory_transaction_init(&state->from);
    platform_directory_transaction_init(&state->to);
    platform_directory_transaction_init(&state->staged);
    platform_directory_transaction_init(&state->prior);
    state->had = false;
}

static void ps_windows_replacement_close(struct ps_windows_replacement *state)
{
    platform_directory_transaction_close(&state->prior);
    platform_directory_transaction_close(&state->staged);
    platform_directory_transaction_close(&state->from);
    platform_directory_transaction_close(&state->to);
}

static bool ps_windows_replacement_open(struct ps_windows_replacement *state,
                                        const char *staging, const char *final_dir)
{
    if (!platform_directory_transaction_parent(staging, &state->from, state->source) ||
        !platform_directory_transaction_parent(final_dir, &state->to, state->target))
        return false;
    if (platform_directory_transaction_open_child_namespace(&state->from, state->source,
                                                            false, &state->staged) !=
        PLATFORM_DIRECTORY_OK)
        return false;
    enum platform_directory_result opened =
        platform_directory_transaction_open_child_namespace(&state->to, state->target,
                                                            false, &state->prior);
    state->had = opened == PLATFORM_DIRECTORY_OK;
    return state->had || opened == PLATFORM_DIRECTORY_MISSING;
}

static bool ps_windows_replacement_aside(struct ps_windows_replacement *state)
{
    if (!state->had)
        return true;
    int n = snprintf(state->aside, sizeof(state->aside), "%s.old.%lu", state->target,
                     (unsigned long)getpid());
    return n > 0 && (size_t)n < sizeof(state->aside) &&
           platform_directory_transaction_move_directory(
               &state->to, state->target, &state->prior, &state->to, state->aside) ==
               PLATFORM_DIRECTORY_OK;
}

static enum plugin_status
ps_windows_replacement_publish(struct ps_windows_replacement *state)
{
    enum platform_directory_result moved =
        platform_directory_transaction_move_directory(
            &state->from, state->source, &state->staged, &state->to, state->target);
    if (moved != PLATFORM_DIRECTORY_OK && moved != PLATFORM_DIRECTORY_OUTCOME_UNKNOWN &&
        state->had)
        (void)platform_directory_transaction_move_directory(
            &state->to, state->aside, &state->prior, &state->to, state->target);
    /* Unknown namespace outcomes retain both staging/aside for reconciliation.
     * Only proven publication permits cleanup of the retained prior object. */
    if (moved == PLATFORM_DIRECTORY_OK && state->had)
        (void)platform_directory_transaction_remove_retained(&state->prior, 0);
    return moved == PLATFORM_DIRECTORY_OK ? PLUGIN_OK : PLUGIN_ERR_IO;
}
#endif

static enum plugin_status ps_replace(const char *gens, const char *staging,
                                     const char *final_dir)
{
#if defined(_WIN32)
    (void)gens;
    struct ps_windows_replacement state;
    ps_windows_replacement_init(&state);
    bool ready = ps_windows_replacement_open(&state, staging, final_dir) &&
                 ps_windows_replacement_aside(&state);
    enum plugin_status status = ready ? ps_windows_replacement_publish(&state) : PLUGIN_ERR_IO;
    ps_windows_replacement_close(&state);
    return status;
#else

    char aside[PLUGIN_PATH_MAX];
    struct stat st;
    bool had = lstat(final_dir, &st) == 0;
    if (had) {
        int n = snprintf(aside, sizeof(aside), "%s.old.%ld", final_dir,
                         (long)getpid());
        if (n <= 0 || (size_t)n >= sizeof(aside) || !plugin_remove_tree(aside) ||
            rename(final_dir, aside) != 0)
            return PLUGIN_ERR_IO;
    }
    if (rename(staging, final_dir) != 0) {
        if (had)
            (void)rename(aside, final_dir);
        return PLUGIN_ERR_IO;
    }
    if (had)
        (void)plugin_remove_tree(aside);
    return plugin_fsync_dir(gens) ? PLUGIN_OK : PLUGIN_ERR_IO;

#endif
}

static enum plugin_status ps_publish(const char *plugdir, const char *name,
                                     const struct ps_paths *src,
                                     const char *keys_file,
                                     struct plugin_manifest *m)
{
    char gens[PLUGIN_PATH_MAX], staging[PLUGIN_PATH_MAX], final_dir[PLUGIN_PATH_MAX];
    char tag[32];
    snprintf(tag, sizeof(tag), "staging.%ld", (long)getpid());
    if (!plugin_join(gens, sizeof(gens), plugdir, "generations", NULL, NULL) ||
        !plugin_join(staging, sizeof(staging), plugdir, tag, NULL, NULL) ||
        !plugin_join(final_dir, sizeof(final_dir), gens, m->generation, NULL, NULL))
        return PLUGIN_ERR_ARGUMENT;
    if (!plugin_mkdirs(gens))
        return PLUGIN_ERR_IO;
    enum plugin_status st = plugin_check_dir(gens);
    if (st == PLUGIN_OK && (!plugin_remove_tree(staging) || !plugin_mkdir_new(staging)))
        st = PLUGIN_ERR_IO;
    if (st == PLUGIN_OK)
        st = ps_stage(src, name, staging, keys_file, m);
    if (st == PLUGIN_OK)
        st = ps_replace(gens, staging, final_dir);
#if !defined(_WIN32)
    if (st != PLUGIN_OK)
        (void)plugin_remove_tree(staging);
#endif
    return st;
}

enum plugin_status plugin_store_install(const char *root,
                                        const char *manifest_path,
                                        struct plugin_manifest *out,
                                        int *already_present)
{
    struct ps_paths src;
    char stem[PLUGIN_NAME_MAX + 1], keys_file[PLUGIN_PATH_MAX], plugdir[PLUGIN_PATH_MAX];
    if (already_present)
        *already_present = 0;
    if (!root || !out)
        return PLUGIN_ERR_ARGUMENT;
    enum plugin_status st = ps_source_paths(manifest_path, stem, &src);
    if (st != PLUGIN_OK)
        return st;
    if (!ps_keys_path(root, keys_file, sizeof(keys_file)))
        return PLUGIN_ERR_ARGUMENT;
    if (plugin_check_dir(root) == PLUGIN_ERR_KEYS_INSECURE)
        return PLUGIN_ERR_KEYS_INSECURE;
    st = ps_verify_set(&src, keys_file, NULL, 0, 0, out);
    if (st == PLUGIN_OK && strcmp(out->name, stem) != 0)
        st = PLUGIN_ERR_MANIFEST_INVALID;
    if (st != PLUGIN_OK)
        return st;
    if (!plugin_join(plugdir, sizeof(plugdir), root, stem, NULL, NULL) ||
        !plugin_mkdirs(plugdir))
        return PLUGIN_ERR_IO;
    st = plugin_check_dir(plugdir);
    if (st != PLUGIN_OK)
        return st;
    if (plugin_verify_generation(root, stem, out->generation) == PLUGIN_OK) {
        if (already_present)
            *already_present = 1;
        return PLUGIN_OK;
    }
    return ps_publish(plugdir, stem, &src, keys_file, out);
}

static enum plugin_status ps_plugin_dir(const char *root, const char *name,
                                        char *plugdir, size_t cap)
{
    if (!root || !plugin_name_valid(name) ||
        !plugin_join(plugdir, cap, root, name, NULL, NULL))
        return PLUGIN_ERR_ARGUMENT;
    enum plugin_status st = plugin_check_dir(root);
    return st == PLUGIN_OK ? plugin_check_dir(plugdir) : st;
}

static enum plugin_status ps_point(const char *plugdir, const char *link,
                                   const char *generation)
{
#if defined(_WIN32)
    char path[PLUGIN_PATH_MAX], pointer[sizeof("generations/") + PLUGIN_HEX_SHA3_512 + 1u];
    int n = snprintf(pointer, sizeof(pointer), "generations/%s\n", generation);
    if (n != (int)(sizeof("generations/") - 1u + PLUGIN_HEX_SHA3_512 + 1u) ||
        !plugin_join(path, sizeof(path), plugdir, link, NULL, NULL))
        return PLUGIN_ERR_ARGUMENT;
    return platform_directory_transaction_write_atomic(path, pointer, (size_t)n) ? PLUGIN_OK : PLUGIN_ERR_IO;
#else

    char target[PLUGIN_PATH_MAX], path[PLUGIN_PATH_MAX];
    snprintf(target, sizeof(target), "generations/%s", generation);
    if (!plugin_join(path, sizeof(path), plugdir, link, NULL, NULL))
        return PLUGIN_ERR_ARGUMENT;
    return platform_atomic_symlink(target, path) == 0 ? PLUGIN_OK : PLUGIN_ERR_IO;

#endif
}

enum plugin_status plugin_store_switch(const char *root, const char *name,
                                       const char *generation)
{
    char plugdir[PLUGIN_PATH_MAX], previous[PLUGIN_HEX_SHA3_512 + 1];
    enum plugin_status st = ps_plugin_dir(root, name, plugdir, sizeof(plugdir));
    if (st == PLUGIN_OK)
        st = plugin_verify_generation(root, name, generation);
    if (st != PLUGIN_OK)
        return st;
    if (plugin_link_generation(plugdir, "current", previous)) {
        if (strcmp(previous, generation) == 0)
            return PLUGIN_OK;
        st = ps_point(plugdir, "last-good", previous);
    }
    return st == PLUGIN_OK ? ps_point(plugdir, "current", generation) : st;
}

enum plugin_status plugin_store_current(const char *root, const char *name,
                                        struct plugin_manifest *out,
                                        char *exe, size_t exe_cap)
{
    char plugdir[PLUGIN_PATH_MAX], generation[PLUGIN_HEX_SHA3_512 + 1];
    enum plugin_status st = ps_plugin_dir(root, name, plugdir, sizeof(plugdir));
    if (st != PLUGIN_OK)
        return st;
    if (!plugin_link_generation(plugdir, "current", generation))
        return PLUGIN_ERR_NO_GENERATION;
    st = plugin_verify_generation_manifest(root, name, generation, out);
    if (st == PLUGIN_OK &&
        !plugin_join(exe, exe_cap, plugdir, "generations", generation, name))
        st = PLUGIN_ERR_ARGUMENT;
    return st;
}

enum plugin_status plugin_store_rollback(const char *root, const char *name,
                                         char restored[PLUGIN_HEX_SHA3_512 + 1])
{
    char plugdir[PLUGIN_PATH_MAX];
    enum plugin_status st = ps_plugin_dir(root, name, plugdir, sizeof(plugdir));
    if (st != PLUGIN_OK)
        return st;
    if (!restored || !plugin_link_generation(plugdir, "last-good", restored))
        return PLUGIN_ERR_NO_LAST_GOOD;
    st = plugin_verify_generation(root, name, restored);
    return st == PLUGIN_OK ? ps_point(plugdir, "current", restored) : st;
}

static int ps_cmp_info(const void *a, const void *b)
{
    const struct plugin_info *x = a, *y = b;
    return strcmp(x->name, y->name);
}

static int ps_cmp_generation(const void *a, const void *b)
{
    return strcmp(a, b);
}

static enum plugin_slot_state ps_open_failure(int err)
{
    if (err == ENOENT)
        return PLUGIN_SLOT_MISSING;
    return err == ENOTDIR || err == ELOOP ? PLUGIN_SLOT_CORRUPT : PLUGIN_SLOT_UNREADABLE;
}

/* Append every generation id in the open directory. A read that fails before
 * the end of the directory leaves what was found unusable: the caller drops it
 * and reports the directory unreadable. */
static enum plugin_status ps_scan_generations(DIR *d, const char *gens,
                                              struct plugin_info *info, bool *complete)
{
    struct dirent *e;
    size_t cap = 0;
    while ((e = ps_readdir(d, gens)) != NULL) {
        if (!plugin_hex_valid(e->d_name, PLUGIN_HEX_SHA3_512))
            continue;
        if (info->generation_count == cap) {
            cap = cap ? cap * 2 : 4;
            void *grown = zcl_realloc(info->generations,
                                      cap * (PLUGIN_HEX_SHA3_512 + 1),
                                      "plugin_generations");
            if (!grown)
                return PLUGIN_ERR_IO;
            info->generations = grown;
        }
        memcpy(info->generations[info->generation_count++], e->d_name,
               PLUGIN_HEX_SHA3_512 + 1);
    }
    *complete = errno == 0;
    return PLUGIN_OK;
}

static enum plugin_status ps_load_generations(const char *plugdir,
                                              struct plugin_info *info)
{
    char gens[PLUGIN_PATH_MAX];
    if (!plugin_join(gens, sizeof(gens), plugdir, "generations", NULL, NULL))
        return PLUGIN_ERR_IO;
    DIR *d = opendir(gens);
    if (!d) {
        info->generations_state = ps_open_failure(errno);
        return PLUGIN_OK;
    }
    bool complete = false;
    enum plugin_status st = ps_scan_generations(d, gens, info, &complete);
    closedir(d);
    if (st != PLUGIN_OK)
        return st;
    if (!complete) {
        free(info->generations);
        info->generations = NULL;
        info->generation_count = 0;
        info->generations_state = PLUGIN_SLOT_UNREADABLE;
        return PLUGIN_OK;
    }
    qsort(info->generations, info->generation_count, PLUGIN_HEX_SHA3_512 + 1,
          ps_cmp_generation);
    return PLUGIN_OK;
}

static enum plugin_status ps_load_info(const char *root, const char *name,
                                       struct plugin_info *info)
{
    char plugdir[PLUGIN_PATH_MAX];
    memset(info, 0, sizeof(*info));
    size_t name_len = strlen(name);
    if (name_len >= sizeof(info->name)) return PLUGIN_ERR_ARGUMENT;
    memcpy(info->name, name, name_len + 1u);
    if (!plugin_join(plugdir, sizeof(plugdir), root, name, NULL, NULL))
        return PLUGIN_ERR_IO;
    info->current_state = plugin_link_slot(plugdir, "current", info->current);
    if (info->current_state != PLUGIN_SLOT_OK)
        info->current[0] = '\0';
    info->last_good_state = plugin_link_slot(plugdir, "last-good", info->last_good);
    if (info->last_good_state != PLUGIN_SLOT_OK)
        info->last_good[0] = '\0';
    return ps_load_generations(plugdir, info);
}

static enum plugin_status ps_collect(DIR *d, const char *root,
                                     struct plugin_info **out, size_t *count)
{
    struct dirent *e;
    size_t cap = 0;
    while ((e = ps_readdir(d, root)) != NULL) {
        char path[PLUGIN_PATH_MAX];
        if (!plugin_name_valid(e->d_name) ||
            !plugin_join(path, sizeof(path), root, e->d_name, NULL, NULL) ||
            !ps_is_dir(path))
            continue;
        if (*count == cap) {
            cap = cap ? cap * 2 : 8;
            struct plugin_info *grown =
                zcl_realloc(*out, cap * sizeof(**out), "plugin_infos");
            if (!grown)
                return PLUGIN_ERR_IO;
            *out = grown;
        }
        if (ps_load_info(root, e->d_name, &(*out)[*count]) != PLUGIN_OK) {
            free((*out)[*count].generations);
            return PLUGIN_ERR_IO;
        }
        (*count)++;
    }
    return errno == 0 ? PLUGIN_OK : PLUGIN_ERR_IO;
}

enum plugin_status plugin_store_list(const char *root,
                                     struct plugin_info **out, size_t *count)
{
    if (!root || !out || !count)
        return PLUGIN_ERR_ARGUMENT;
    *out = NULL;
    *count = 0;
    DIR *d = opendir(root);
    if (!d)
        return errno == ENOENT ? PLUGIN_OK : PLUGIN_ERR_IO;
    enum plugin_status st = ps_collect(d, root, out, count);
    closedir(d);
    if (st != PLUGIN_OK) {
        plugin_store_list_free(*out, *count);
        *out = NULL;
        *count = 0;
        return st;
    }
    qsort(*out, *count, sizeof(**out), ps_cmp_info);
    return PLUGIN_OK;
}

void plugin_store_list_free(struct plugin_info *infos, size_t count)
{
    for (size_t i = 0; infos && i < count; i++)
        free(infos[i].generations);
    free(infos);
}

static enum plugin_status ps_keys_dirs(const char *root)
{
    char parent[PLUGIN_PATH_MAX];
    const char *slash = strrchr(root, '/');
    if (!slash || slash == root || (size_t)(slash - root) >= sizeof(parent))
        return PLUGIN_ERR_ARGUMENT;
    memcpy(parent, root, (size_t)(slash - root));
    parent[slash - root] = '\0';
    const char *dirs[2] = { parent, root };
    for (int i = 0; i < 2; i++) {
        enum plugin_status st = plugin_check_dir(dirs[i]);
        if (st != PLUGIN_OK && st != PLUGIN_ERR_NOT_INSTALLED)
            return st;
    }
    return plugin_mkdirs(root) ? PLUGIN_OK : PLUGIN_ERR_IO;
}

static bool ps_keys_has(const char *bytes, size_t len, const char *key)
{
    size_t pos = 0;
    while (pos < len) {
        size_t end = pos;
        while (end < len && bytes[end] != '\n')
            end++;
        size_t n = end - pos;
        if (n > 0 && bytes[pos + n - 1] == '\r')
            n--;
        if (n == PLUGIN_HEX_PUBLIC_KEY && memcmp(bytes + pos, key, n) == 0)
            return true;
        pos = end + 1;
    }
    return false;
}

/* Replaces path through an exclusive sibling and a rename; owner-only file. */
static bool ps_write_private(const char *path, const char *data, size_t len)
{
#if defined(_WIN32)
    return platform_directory_transaction_write_atomic(path, data, len);
#else

    char tmp[PLUGIN_PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(tmp))
        return false;
    (void)unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    bool ok = fchmod(fd, 0600) == 0 && write(fd, data, len) == (ssize_t)len &&
              fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    ok = ok && rename(tmp, path) == 0;
    if (!ok)
        (void)unlink(tmp);
    return ok;

#endif
}

static enum plugin_status ps_keys_append(const char *root, const char *path,
                                          const char *key,
                                          char *bytes, size_t len)
{
    if (len > PLUGIN_FILE_MAX - PLUGIN_HEX_PUBLIC_KEY - 2)
        return PLUGIN_ERR_KEYS_MALFORMED; /* plugin_keys_load would refuse the result */
    char *out = zcl_malloc(len + PLUGIN_HEX_PUBLIC_KEY + 2, "plugin_store_add_key");
    if (!out)
        return PLUGIN_ERR_IO;
    size_t n = len;
    if (len > 0)
        memcpy(out, bytes, len);
    if (len > 0 && out[len - 1] != '\n')
        out[n++] = '\n';
    memcpy(out + n, key, PLUGIN_HEX_PUBLIC_KEY);
    n += PLUGIN_HEX_PUBLIC_KEY;
    out[n++] = '\n';
    enum plugin_status st = ps_write_private(path, out, n) ? PLUGIN_OK : PLUGIN_ERR_IO;
    if (st == PLUGIN_OK && !plugin_fsync_dir(root))
        st = PLUGIN_ERR_IO;
    free(out);
    return st;
}

enum plugin_status plugin_store_add_key(const char *root, const char *key,
                                      int *already_listed)
{
    char path[PLUGIN_PATH_MAX], *bytes = NULL;
    size_t len = 0;
    if (!root || !key || !already_listed || !plugin_hex_valid(key, PLUGIN_HEX_PUBLIC_KEY) ||
        !ps_keys_path(root, path, sizeof(path)))
        return PLUGIN_ERR_ARGUMENT;
    enum plugin_status st = ps_keys_dirs(root);
    if (st != PLUGIN_OK)
        return st;
    st = plugin_keys_load(path, &bytes, &len);
    if (st == PLUGIN_ERR_NO_KEYS && access(path, F_OK) != 0)
        st = PLUGIN_OK; /* no key file yet: bytes stays NULL, len 0 */
    else if (st == PLUGIN_ERR_NO_KEYS)
        st = PLUGIN_ERR_IO;
    if (st != PLUGIN_OK)
        return st;
    *already_listed = bytes && ps_keys_has(bytes, len, key);
    if (!*already_listed)
        st = ps_keys_append(root, path, key, bytes, len);
    free(bytes);
    return st;
}
