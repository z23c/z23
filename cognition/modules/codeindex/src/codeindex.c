/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex — public lifecycle: open (verify-on-read, lazily rebuild if the
 * source tree changed) and close. Queries live in codeindex_query.c; the
 * rebuild/staleness machinery in codeindex_build.c. */

#include "codeindex_priv.h"
#include "codeindex/codeindex_merkle.h"
#include "codeindex/codeindex_build.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
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

struct codeindex *codeindex_open_retrieval_view(const char *root)
{
    struct codeindex *ci = codeindex_open_source_view(root);
    if (!ci) return NULL;
    bool valid = false;
    if (!ci_store_retrieval_projection_is_valid(ci->store, &valid)) {
        codeindex_close(ci);
        return NULL;
    }
    if (!valid) {
        if (!codeindex_rebuild(ci) ||
            !ci_store_retrieval_projection_is_valid(ci->store, &valid) ||
            !valid) {
            codeindex_close(ci);
            LOG_NULL("codeindex", "retrieval projection rebuild failed");
        }
    }
    return ci;
}

void codeindex_close(struct codeindex *ci)
{
    if (!ci) return;
    if (ci->store) ci_store_close(ci->store);
    ci_merkle_free(ci->pending_merkle);
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

bool codeindex_build_cold_ms(struct codeindex *ci, long long *ms_out,
                             long long *files_out)
{
    if (ms_out) *ms_out = 0;
    if (files_out) *files_out = 0;
    if (!ci || !ci->store || !ms_out || !files_out)
        LOG_FAIL("codeindex", "null arg to build_cold_ms");
    char ms_text[24], files_text[24];
    size_t ms_len = 0, files_len = 0;
    bool ms_found = false, files_found = false;
    if (!ci_store_meta_get(ci->store, "build_cold_ms", ms_text,
                           sizeof(ms_text) - 1, &ms_len, &ms_found) ||
        !ci_store_meta_get(ci->store, "build_cold_files", files_text,
                           sizeof(files_text) - 1, &files_len, &files_found))
        LOG_FAIL("codeindex", "read cold-build receipt failed");
    /* Stores built before the self-receipt existed simply lack the keys;
     * that absence is a valid observation of an older generation, not a
     * hard failure. */
    if (!ms_found || !files_found || ms_len == 0 || files_len == 0)
        return false;
    ms_text[ms_len] = '\0';
    files_text[files_len] = '\0';
    char *ms_end = NULL, *files_end = NULL;
    long long ms = strtoll(ms_text, &ms_end, 10);
    long long files = strtoll(files_text, &files_end, 10);
    if (!ms_end || *ms_end != '\0' || !files_end || *files_end != '\0' ||
        ms < 0 || files < 0)
        return false;
    *ms_out = ms;
    *files_out = files;
    return true;
}

bool codeindex_retrieval_projection_root_sha3(struct codeindex *ci,
                                              uint8_t out[32])
{
    if (!ci || !ci->store || !out)
        LOG_FAIL("codeindex", "null arg to retrieval_projection_root_sha3");
    uint8_t root[32];
    size_t len = 0;
    bool found = false;
    if (!ci_store_meta_get(ci->store, CI_RETRIEVAL_PROJECTION_META, root,
                           sizeof(root), &len, &found))
        LOG_FAIL("codeindex", "read retrieval projection root");
    if (!found || len != sizeof(root))
        LOG_FAIL("codeindex", "invalid retrieval projection root metadata");
    memcpy(out, root, sizeof(root));
    return true;
}

bool codeindex_retrieval_projection_is_current(struct codeindex *ci,
                                               bool *current)
{
    if (current) *current = false;
    if (!ci || !ci->store || !current)
        LOG_FAIL("codeindex", "null arg to retrieval_projection_is_current");
    return ci_store_retrieval_projection_is_valid(ci->store, current);
}
