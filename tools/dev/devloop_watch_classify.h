/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private seam between the watcher shell (devloop_watch.c) and its
 * pure edit-classification core (devloop_watch_classify.c). Only those two
 * files and the HOT_FORK story adapter devloop_watch_classification_core_v1
 * include it. */
#ifndef ZCL_TOOLS_DEV_DEVLOOP_WATCH_CLASSIFY_H
#define ZCL_TOOLS_DEV_DEVLOOP_WATCH_CLASSIFY_H

#include <stdbool.h>
#include <stddef.h>

/* True when `path` names a C translation unit (ends in lowercase ".c"). */
bool zcl_devloop_watch_c_source(const char *path);

/* True when every one of `path_count` (>0) paths is a C translation unit. */
bool zcl_devloop_watch_epoch_all_c(const char *const *paths,
                                   size_t path_count);

/* Writes the shared two-level component ("tools/dev") of `files` to `out`,
 * "mixed" when they differ, or the bare name of a root-level file. */
void zcl_devloop_watch_component_for_files(const char *const *files,
                                           size_t count, char out[128]);

#endif /* ZCL_TOOLS_DEV_DEVLOOP_WATCH_CLASSIFY_H */
