/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex — public lifecycle: open (verify-on-read, lazily rebuild if the
 * source tree changed) and close. Queries live in codeindex_query.c; the
 * rebuild/staleness machinery in codeindex_build.c. */

#include "codeindex_priv.h"
#include "codeindex/codeindex_build.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <string.h>

static struct codeindex *codeindex_alloc(const char *root)
{
    if (!root || !root[0])
        LOG_NULL("codeindex", "null root");

    struct codeindex *ci = zcl_calloc(1, sizeof(*ci), "codeindex");
    if (!ci)
        LOG_NULL("codeindex", "calloc codeindex");

    int n = snprintf(ci->root, sizeof(ci->root), "%s", root);
    if (n <= 0 || (size_t)n >= sizeof(ci->root)) {
        free(ci);
        LOG_NULL("codeindex", "root too long");
    }

    return ci;
}

struct codeindex *codeindex_open_existing(const char *root)
{
    struct codeindex *ci = codeindex_alloc(root);
    if (!ci) return NULL;
    ci->store = ci_store_open(root);
    if (!ci->store) {
        codeindex_close(ci);
        return NULL;
    }
    return ci;
}

struct codeindex *codeindex_open(const char *root)
{
    struct codeindex *ci = codeindex_alloc(root);
    if (!ci) return NULL;
    bool stale = true;
    ci->store = ci_store_open(root);
    if (ci->store && !codeindex_is_stale(ci, &stale)) {
        /* A derived store with a damaged/unreadable freshness record is not
         * authority. Drop that reader and recompute under the single-flight
         * publication lock instead of failing or repairing in place. */
        ci_store_close(ci->store);
        ci->store = NULL;
        stale = true;
    }
    if (!ci->store || stale) {
        if (!ci_codeindex_refresh(ci)) {
            codeindex_close(ci);
            LOG_NULL("codeindex", "rebuild failed");
        }
    }
    return ci;
}

struct codeindex *codeindex_open_source_view(const char *root)
{
    struct codeindex *ci = codeindex_alloc(root);
    if (!ci) return NULL;
    bool stale = true;
    ci->store = ci_store_open(root);
    if (ci->store && !ci_codeindex_source_view_is_stale(ci, &stale)) {
        ci_store_close(ci->store);
        ci->store = NULL;
        stale = true;
    }
    if (!ci->store || stale) {
        if (!ci_codeindex_refresh(ci)) {
            codeindex_close(ci);
            LOG_NULL("codeindex", "source-view rebuild failed");
        }
    }
    return ci;
}

void codeindex_close(struct codeindex *ci)
{
    if (!ci) return;
    if (ci->store) ci_store_close(ci->store);
    free(ci);
}

bool codeindex_source_root_sha3(struct codeindex *ci, uint8_t out[32])
{
    if (!ci || !ci->store || !out)
        LOG_FAIL("codeindex", "null arg to source_root_sha3");
    size_t len = 0;
    bool found = false;
    if (!ci_store_meta_get(ci->store, "source_root_sha3", out, 32, &len,
                           &found))
        LOG_FAIL("codeindex", "read source_root_sha3");
    if (!found || len != 32)
        LOG_FAIL("codeindex", "invalid source_root_sha3 metadata");
    return true;
}
