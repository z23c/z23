/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.index source registry — see native_dev_index_catalog.h. Everything
 * here is derived from engine/composition/sources.def: no source path is
 * hand-rolled a second time.
 */

#include "command/native_dev_index_catalog.h"

#include "platform/directory_compat.h"
#include "platform/state_root.h"
#include "services/evidence_ledger_row.h"

#include <stdio.h>
#include <string.h>

#define DEV_INDEX_ZCLASSIC23_ENV "ZCL_INDEX_STATE_DIR"
#define DEV_INDEX_ZCLASSIC23_HOME_REL ".local/state/zclassic23"

/* One row per Z23_SOURCE(id_, kind_, root_, path_, format_, why_) in
 * sources.def. path_ is parsed once here into (dir_rel, suffix|file_name,
 * recursive) so the registry stays the one place a source's shape lives. */
struct dev_index_source_decl {
    const char *id;
    enum dev_index_kind kind;
    const char *root_tag; /* "ZCLASSIC23" or "DEV_STATE" */
    const char *path;
    enum dev_index_format format;
    const char *why;
};

#define ZCLASSIC23_TAG "ZCLASSIC23"
#define DEV_STATE_TAG "DEV_STATE"

static const struct dev_index_source_decl g_decls[] = {
#define jsonl DEV_INDEX_FORMAT_JSONL
#define tsv DEV_INDEX_FORMAT_TSV
#define text_kv DEV_INDEX_FORMAT_TEXT_KV
#define board_rows DEV_INDEX_KIND_BOARD_ROWS
#define experiment_rows DEV_INDEX_KIND_EXPERIMENT_ROWS
#define landing_outcomes DEV_INDEX_KIND_LANDING_OUTCOMES
#define log_lines DEV_INDEX_KIND_LOG_LINES
#define ZCLASSIC23 ZCLASSIC23_TAG
#define DEV_STATE DEV_STATE_TAG
#define Z23_SOURCE(id_, kind_, root_, path_, format_, why_) \
    { (id_), (kind_), (root_), (path_), (format_), (why_) },
#include "../../engine/composition/sources.def"
#undef Z23_SOURCE
#undef ZCLASSIC23
#undef DEV_STATE
#undef jsonl
#undef tsv
#undef text_kv
#undef board_rows
#undef experiment_rows
#undef landing_outcomes
#undef log_lines
};

#define DEV_INDEX_SOURCE_COUNT (sizeof(g_decls) / sizeof(g_decls[0]))

/* Parsed, ready-to-use rows: computed once from g_decls at first use. */
static struct dev_index_source g_sources[DEV_INDEX_SOURCE_COUNT];
static bool g_sources_ready;

/* Splits a declared source path — a directory plus either a star-suffix
 * glob leaf or one literal file name, optionally prefixed with a
 * recursive-marker leading segment — into the fields struct
 * dev_index_source needs. Buffers backing dir_rel/suffix/file_name are
 * static storage sized to the declared path, never freed, never mutated
 * after parse. */
static char g_dir_rel[DEV_INDEX_SOURCE_COUNT][256];
static char g_leaf[DEV_INDEX_SOURCE_COUNT][256];

static void dev_index_parse_path(size_t slot, const char *path,
                                 struct dev_index_source *out)
{
    bool recursive = strncmp(path, "**/", 3) == 0;
    const char *rest = recursive ? path + 3 : path;
    const char *slash = strrchr(rest, '/');
    const char *leaf = slash ? slash + 1 : rest;
    size_t dir_len = slash ? (size_t)(slash - rest) : 0;
    if (dir_len >= sizeof(g_dir_rel[slot]))
        dir_len = sizeof(g_dir_rel[slot]) - 1;
    if (dir_len > 0)
        memcpy(g_dir_rel[slot], rest, dir_len);
    g_dir_rel[slot][dir_len] = '\0';
    (void)snprintf(g_leaf[slot], sizeof(g_leaf[slot]), "%s", leaf);

    out->dir_rel = g_dir_rel[slot];
    out->recursive = recursive;
    if (leaf[0] == '*') {
        out->suffix = g_leaf[slot] + 1; /* skip the leading '*' */
        out->file_name = "";
    } else {
        out->suffix = "";
        out->file_name = g_leaf[slot];
    }
}

static void dev_index_build_sources(void)
{
    if (g_sources_ready)
        return;
    for (size_t i = 0; i < DEV_INDEX_SOURCE_COUNT; i++) {
        const struct dev_index_source_decl *d = &g_decls[i];
        g_sources[i].id = d->id;
        g_sources[i].kind = d->kind;
        g_sources[i].format = d->format;
        g_sources[i].why = d->why;
        g_sources[i].dev_state_root = strcmp(d->root_tag, DEV_STATE_TAG) == 0;
        dev_index_parse_path(i, d->path, &g_sources[i]);
    }
    g_sources_ready = true;
}

size_t dev_index_source_count(void)
{
    dev_index_build_sources();
    return DEV_INDEX_SOURCE_COUNT;
}

const struct dev_index_source *dev_index_source_at(size_t index)
{
    dev_index_build_sources();
    if (index >= DEV_INDEX_SOURCE_COUNT)
        return NULL;
    return &g_sources[index];
}

const struct dev_index_source *dev_index_source_find(const char *id)
{
    if (!id || !id[0])
        return NULL;
    dev_index_build_sources();
    for (size_t i = 0; i < DEV_INDEX_SOURCE_COUNT; i++)
        if (strcmp(g_sources[i].id, id) == 0)
            return &g_sources[i];
    return NULL;
}

bool dev_index_source_resolve_root(const struct dev_index_source *src,
                                   char *out, size_t cap)
{
    if (!src || !out || cap == 0)
        return false;
    if (src->dev_state_root)
        return platform_state_root(out, cap);
    char resolved[1024];
    if (!evidence_ledger_resolve_path(DEV_INDEX_ZCLASSIC23_ENV,
                                      DEV_INDEX_ZCLASSIC23_HOME_REL, ".",
                                      resolved, sizeof(resolved)))
        return false;
    size_t n = strlen(resolved);
    if (n >= 2 && resolved[n - 1] == '.' && resolved[n - 2] == '/')
        resolved[n - 2] = '\0';
    if (snprintf(out, cap, "%s", resolved) >= (int)cap)
        return false;
    return true;
}

static bool dev_index_dir_path(const struct dev_index_source *src, char *out,
                               size_t cap)
{
    char root[1024];
    if (!dev_index_source_resolve_root(src, root, sizeof(root)))
        return false;
    if (src->dir_rel[0] == '\0')
        return snprintf(out, cap, "%s", root) < (int)cap;
    return snprintf(out, cap, "%s/%s", root, src->dir_rel) < (int)cap;
}

static bool dev_index_suffix_match(const char *name, const char *suffix)
{
    size_t nlen = strlen(name), slen = strlen(suffix);
    return nlen >= slen && strcmp(name + (nlen - slen), suffix) == 0;
}

/* Recursive walk bound: the fleet's real state root is a handful of
 * directories deep at most; this stops a symlink-free but deeply nested
 * tree from ever running unbounded. */
#define DEV_INDEX_WALK_MAX_DEPTH 8

static size_t dev_index_walk(const char *dir, const char *suffix,
                             bool recursive, int depth, char out[][1024],
                             size_t out_cap, size_t path_cap, size_t written)
{
    if (depth > DEV_INDEX_WALK_MAX_DEPTH || written >= out_cap)
        return written;
    struct platform_directory_list files, dirs;
    memset(&files, 0, sizeof(files));
    memset(&dirs, 0, sizeof(dirs));
    if (!platform_directory_list_children_sorted(dir, &dirs, &files))
        return written;
    for (size_t i = 0; i < files.count && written < out_cap; i++) {
        const char *name = files.entries[i].name;
        if (!dev_index_suffix_match(name, suffix))
            continue;
        if ((size_t)snprintf(out[written], path_cap, "%s/%s", dir, name) >=
            path_cap)
            continue;
        written++;
    }
    if (recursive) {
        for (size_t i = 0; i < dirs.count && written < out_cap; i++) {
            char sub[1024];
            if ((size_t)snprintf(sub, sizeof(sub), "%s/%s", dir,
                                 dirs.entries[i].name) >= sizeof(sub))
                continue;
            written = dev_index_walk(sub, suffix, recursive, depth + 1, out,
                                     out_cap, path_cap, written);
        }
    }
    platform_directory_list_free(&files);
    platform_directory_list_free(&dirs);
    return written;
}

size_t dev_index_source_list_files(const struct dev_index_source *src,
                                   char out[][1024], size_t out_cap,
                                   size_t path_cap)
{
    if (!src || !out || out_cap == 0)
        return 0;
    char dir[1024];
    if (!dev_index_dir_path(src, dir, sizeof(dir)))
        return 0;
    if (src->file_name[0] != '\0') {
        if ((size_t)snprintf(out[0], path_cap, "%s/%s", dir,
                             src->file_name) >= path_cap)
            return 0;
        return 1;
    }
    return dev_index_walk(dir, src->suffix, src->recursive, 0, out, out_cap,
                          path_cap, 0);
}
