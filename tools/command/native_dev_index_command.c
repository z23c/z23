/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.index.{ingest,status,search} — see docs/INDEX.md and
 * engine/composition/sources.def. This file only wires the three CLI
 * verbs to the catalog/ingest/search modules; it owns no sqlite calls of
 * its own.
 */

#include "command/native_command.h"
#include "command/native_dev_index_catalog.h"
#include "command/native_dev_index_ingest.h"
#include "command/native_dev_index_search.h"

#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/clock.h"

#include <sqlite3.h>
#include <string.h>

#define DVI_ERR_MAX 256u

static bool dvi_open(struct zcl_command_reply *reply, const char *leaf,
                     sqlite3 **db)
{
    char err[DVI_ERR_MAX];
    if (dev_index_db_open(db, err, sizeof(err)))
        return true;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INTERNAL, "INDEX_DB_ERROR", leaf,
                           false, false, err, "");
    return false;
}

/* Sources named by --source=<id> (or every declared source when absent);
 * returns the number selected into out[], up to `cap`. -1 means the named
 * source does not exist. */
static int dvi_select_sources(const char *only_id,
                              const struct dev_index_source **out,
                              size_t cap)
{
    if (only_id && only_id[0]) {
        const struct dev_index_source *s = dev_index_source_find(only_id);
        if (!s)
            return -1;
        if (cap > 0)
            out[0] = s;
        return 1;
    }
    size_t n = dev_index_source_count();
    size_t written = 0;
    for (size_t i = 0; i < n && written < cap; i++)
        out[written++] = dev_index_source_at(i);
    return (int)written;
}

void zcl_native_handle_dev_index_ingest(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *only = json_get_str(json_get(request->input, "source"));
    const struct dev_index_source *sources[16];
    int n = dvi_select_sources(only, sources, 16);
    if (n < 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "SOURCE_UNKNOWN",
                               "dev.index.ingest", false, false,
                               "no such source id", only ? only : "");
        return;
    }
    sqlite3 *db = NULL;
    if (!dvi_open(reply, "dev.index.ingest", &db))
        return;

    struct json_value sources_arr;
    json_init(&sources_arr);
    json_set_array(&sources_arr);
    int64_t total_rows = 0, total_files = 0;
    char err[DVI_ERR_MAX];
    for (int i = 0; i < n; i++) {
        struct dev_index_ingest_result result;
        if (!dev_index_ingest_source(db, sources[i], &result, err,
                                     sizeof(err))) {
            json_free(&sources_arr);
            dev_index_db_close(db);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL,
                                   "INDEX_INGEST_ERROR", "dev.index.ingest",
                                   true, true, err, sources[i]->id);
            return;
        }
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "source", result.source_id);
        (void)json_push_kv_int(&row, "files_seen", result.files_seen);
        (void)json_push_kv_int(&row, "rows_added", result.rows_added);
        (void)json_push_back(&sources_arr, &row);
        json_free(&row);
        total_rows += result.rows_added;
        total_files += result.files_seen;
    }
    dev_index_db_close(db);
    (void)json_push_kv(&reply->data, "sources", &sources_arr);
    json_free(&sources_arr);
    (void)json_push_kv_int(&reply->data, "files_seen", total_files);
    (void)json_push_kv_int(&reply->data, "rows_added", total_rows);
}

void zcl_native_handle_dev_index_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *only = json_get_str(json_get(request->input, "source"));
    const struct dev_index_source *sources[16];
    int n = dvi_select_sources(only, sources, 16);
    if (n < 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "SOURCE_UNKNOWN",
                               "dev.index.status", false, false,
                               "no such source id", only ? only : "");
        return;
    }
    sqlite3 *db = NULL;
    if (!dvi_open(reply, "dev.index.status", &db))
        return;

    int64_t now_ms = clock_now_wall_ms();
    struct json_value sources_arr;
    json_init(&sources_arr);
    json_set_array(&sources_arr);
    char err[DVI_ERR_MAX];
    for (int i = 0; i < n; i++) {
        struct dev_index_source_status st;
        if (!dev_index_source_status(db, sources[i], now_ms, &st, err,
                                     sizeof(err))) {
            json_free(&sources_arr);
            dev_index_db_close(db);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL,
                                   "INDEX_STATUS_ERROR", "dev.index.status",
                                   true, false, err, sources[i]->id);
            return;
        }
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "source", st.source_id);
        (void)json_push_kv_int(&row, "rows", st.rows);
        (void)json_push_kv_str(&row, "newest_ts", st.newest_ts);
        (void)json_push_kv_int(&row, "seconds_since_newest",
                               st.seconds_since_newest);
        (void)json_push_kv_int(&row, "bytes_behind", st.bytes_behind);
        (void)json_push_back(&sources_arr, &row);
        json_free(&row);
    }
    dev_index_db_close(db);
    (void)json_push_kv(&reply->data, "sources", &sources_arr);
    json_free(&sources_arr);
}

void zcl_native_handle_dev_index_search(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *query = json_get_str(json_get(request->input, "query"));
    if (!query || !query[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_INPUT",
                               "dev.index.search", false, false,
                               "query must be non-empty", "");
        return;
    }
    const char *source = json_get_str(json_get(request->input, "source"));
    if (source && source[0] && !dev_index_source_find(source)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "SOURCE_UNKNOWN",
                               "dev.index.search", false, false,
                               "no such source id", source);
        return;
    }
    const struct json_value *limit_v = json_get(request->input, "limit");
    size_t limit = (limit_v && limit_v->type == JSON_INT &&
                   json_get_int(limit_v) > 0)
                      ? (size_t)json_get_int(limit_v)
                      : DEV_INDEX_SEARCH_DEFAULT_LIMIT;

    sqlite3 *db = NULL;
    if (!dvi_open(reply, "dev.index.search", &db))
        return;
    struct dev_index_search_result result;
    char err[DVI_ERR_MAX];
    if (!dev_index_search(db, query, source, limit, &result, err,
                          sizeof(err))) {
        dev_index_db_close(db);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "SEARCH_ERROR",
                               "dev.index.search", false, false, err, query);
        return;
    }
    dev_index_db_close(db);

    struct json_value hits;
    json_init(&hits);
    json_set_array(&hits);
    for (size_t i = 0; i < result.count; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "source", result.hits[i].source_id);
        (void)json_push_kv_str(&row, "ts", result.hits[i].ts);
        (void)json_push_kv_str(&row, "text", result.hits[i].text);
        (void)json_push_back(&hits, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "hits", &hits);
    json_free(&hits);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)result.count);
}
