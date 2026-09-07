/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: dev.index source registry accessors over
 * engine/composition/sources.def (tools/command/native_dev_index_catalog.c). */
#ifndef ZCL_NATIVE_DEV_INDEX_CATALOG_H
#define ZCL_NATIVE_DEV_INDEX_CATALOG_H

#include <stdbool.h>
#include <stddef.h>

enum dev_index_kind {
    DEV_INDEX_KIND_BOARD_ROWS,
    DEV_INDEX_KIND_EXPERIMENT_ROWS,
    DEV_INDEX_KIND_LANDING_OUTCOMES,
    DEV_INDEX_KIND_LOG_LINES,
};

enum dev_index_format {
    DEV_INDEX_FORMAT_JSONL,
    DEV_INDEX_FORMAT_TSV,
    DEV_INDEX_FORMAT_TEXT_KV,
};

/* One declared source, derived at compile time from sources.def. */
struct dev_index_source {
    const char *id;
    enum dev_index_kind kind;
    enum dev_index_format format;
    const char *why;
    bool dev_state_root;   /* true: platform_state_root(); false: the
                            * ".local/state/zclassic23" fleet root. */
    const char *dir_rel;   /* directory the file(s) live in, relative to the
                            * resolved root; "" means the root itself. */
    const char *suffix;    /* non-empty: every regular file under dir_rel
                            * ending in this suffix is a match (a glob
                            * source). Mutually exclusive with file_name. */
    const char *file_name; /* non-empty: exactly this one literal file name
                            * under dir_rel. Mutually exclusive with suffix. */
    bool recursive;        /* glob sources only: also search
                            * subdirectories under dir_rel. */
};

size_t dev_index_source_count(void);
const struct dev_index_source *dev_index_source_at(size_t index);
const struct dev_index_source *dev_index_source_find(const char *id);

/* Resolve the source's root directory: `state_root_override` when non-empty
 * (the CLI's --state-root=<dir>, applied to every source regardless of
 * dev_state_root, for test isolation and deliberate redirection), else the
 * zclassic23 state root or the native dev-state root per dev_state_root.
 * Does not create anything, does not append dir_rel. No environment
 * variable is consulted here — --state-root is the only override. */
bool dev_index_source_resolve_root(const struct dev_index_source *src,
                                   const char *state_root_override,
                                   char *out, size_t cap);

/* List every file this source currently names (glob-expanded for a suffix
 * source, or the single literal path otherwise) into out[0..count), each up
 * to cap bytes, newest-name-last (bytewise directory order). Returns the
 * number written (0 on a source with no files yet, never an error). */
size_t dev_index_source_list_files(const struct dev_index_source *src,
                                   const char *state_root_override,
                                   char out[][1024], size_t out_cap,
                                   size_t path_cap);

#endif /* ZCL_NATIVE_DEV_INDEX_CATALOG_H */
