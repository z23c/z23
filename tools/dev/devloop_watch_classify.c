/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the watcher's pure edit-classification core — which saved paths
 * are C translation units and which component an edit epoch belongs to —
 * split out of devloop_watch.c so the HOT_FORK story
 * devloop-watch-classification-core.v1 compiles this small file instead of
 * the whole watcher. Deterministic and effect-free: reads caller-owned
 * strings, writes only the caller's output buffer, owns no file-scope state.
 * Behaviour is unchanged from its former static copies in devloop_watch.c. */

#include "devloop_watch_classify.h"

#include <stdio.h>
#include <string.h>

bool zcl_devloop_watch_c_source(const char *path)
{
    size_t n = path ? strlen(path) : 0;
    return n > 2 && path[n - 2] == '.' && path[n - 1] == 'c';
}

bool zcl_devloop_watch_epoch_all_c(const char *const *paths,
                                   size_t path_count)
{
    if (!paths || path_count == 0)
        return false;
    for (size_t i = 0; i < path_count; i++)
        if (!zcl_devloop_watch_c_source(paths[i]))
            return false;
    return true;
}

void zcl_devloop_watch_component_for_files(const char *const *files,
                                           size_t count, char out[128])
{
    out[0] = 0;
    for (size_t i = 0; i < count; i++) {
        char component[128];
        const char *first = strchr(files[i], '/');
        const char *second = first ? strchr(first + 1, '/') : NULL;
        size_t len = second ? (size_t)(second - files[i]) : strlen(files[i]);
        if (len >= sizeof(component))
            len = sizeof(component) - 1;
        memcpy(component, files[i], len);
        component[len] = 0;
        if (i == 0)
            (void)snprintf(out, 128, "%s", component);
        else if (strcmp(out, component) != 0) {
            (void)snprintf(out, 128, "%s", "mixed");
            return;
        }
    }
}
