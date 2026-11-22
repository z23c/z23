/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the land receiver pool of the host-GC sweep (declared in
 *          command/host_gc_priv.h and host_gc_sweep.h). `dev land receive`
 *          places one detached copy per lane under
 *          <state root>/land-remote/<lane> for the queue to read; it takes no
 *          sibling lock and keeps no process open on the copy, so the
 *          disposable-pool lock rules cannot see that a row still needs it.
 *          The queue itself is the authority on that: a copy is held while a
 *          queued or inflight row has the copy's HEAD as its tip. Rows come
 *          from the existing read-only view (zcl_dev_land_rows_read); this
 *          file keeps no state of its own and writes nothing.
 *
 *          Fail closed: a queue that cannot be read, or a copy whose HEAD
 *          cannot be read, holds the copy.
 */

#include "command/host_gc_priv.h"

#include "command/native_dev_land_read.h"
#include "platform/state_root.h"
#include "util/path_util.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

enum { HG_LAND_TIP = 12 };

struct hg_land_view {
    struct zcl_dl_row_view *rows;
    size_t n;
    bool unreadable;
};

struct hg_land_view *hg_land_view_load(void)
{
    struct hg_land_view *v = zcl_calloc(1, sizeof(*v), "host_gc land view");
    if (!v)
        return NULL;
    if (!zcl_dev_land_rows_read(&v->rows, &v->n, NULL)) {
        v->rows = NULL;
        v->n = 0;
        v->unreadable = true;
    }
    return v;
}

void hg_land_view_free(struct hg_land_view *view)
{
    if (!view)
        return;
    free(view->rows);
    free(view);
}

/* Non-terminal in the land queue's own sense (dl_terminal_state): the row can
 * still run, retry or be re-driven, and reads its copy when it does. */
static bool hg_land_row_live(const struct zcl_dl_row_view *row)
{
    return strcmp(row->state, "queued") == 0 ||
           strcmp(row->state, "inflight") == 0;
}

bool hg_land_view_holds(const struct hg_land_view *view, const char *head)
{
    if (!view || view->unreadable || !head)
        return true;
    for (size_t i = 0; i < view->n; i++)
        if (hg_land_row_live(&view->rows[i]) &&
            strncmp(head, view->rows[i].tip12, HG_LAND_TIP) == 0)
            return true;
    return false;
}

bool host_gc_add_land_pool(struct host_gc_request *req)
{
    char state[HOST_GC_PATH_CAP];
    struct host_gc_pool *pool;
    struct stat st;
    if (!req || req->npools >= HOST_GC_MAX_POOLS ||
        !platform_state_root_existing(state, sizeof(state)))
        return false;
    pool = &req->pools[req->npools];
    memset(pool, 0, sizeof(*pool));
    if (!zcl_path_join(pool->path, sizeof(pool->path), state, "land-remote") ||
        !hg_copy(pool->name, sizeof(pool->name), "land-remote") ||
        stat(pool->path, &st) != 0 || !S_ISDIR(st.st_mode))
        return false;
    pool->disposable = true;
    pool->queue_gated = true;
    req->npools++;
    return true;
}
