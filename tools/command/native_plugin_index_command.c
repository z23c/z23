/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: plugin.index_add and plugin.search — the local signed plugin index.
 *          index_add signs one entry for a packed plugin and writes it into an
 *          index directory; search lists the verified entries of a directory,
 *          marks each publisher pinned or unpinned and changes nothing. Neither
 *          contacts the daemon, and neither fetches or installs a plugin. */

#include "command/native_command.h"

#include "json/json.h"
#include "plugin/plugin_index.h"
#include "plugin/plugin_pack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *pix_str(const struct zcl_command_request *request,
                           const char *key)
{
    const struct json_value *v = request->input ? json_get(request->input, key)
                                                : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static void pix_refuse(struct zcl_command_reply *reply, const char *code,
                       const char *next_action, const char *what,
                       const char *evidence)
{
    char message[192];
    (void)snprintf(message, sizeof(message), "plugin %s refused: %s", what, code);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, what, false, false,
                           message, evidence ? evidence : "");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", next_action);
    reply->error.human_action_required = true;
}

static const char *pix_next_action(enum plugin_index_status st)
{
    switch (st) {
    case PLUGIN_INDEX_ROLLBACK:
        return "publish a version at or above the newest one already in the index";
    case PLUGIN_INDEX_EQUIVOCATION:
        return "use a new version for a different root; one version names one package";
    case PLUGIN_INDEX_PINS:
        return "pass --publishers=FILE, a file of 64-hex public keys, one per line, owned by you and closed to group and others";
    case PLUGIN_INDEX_TOO_MANY:
        return "split the index directory; one directory holds at most 4096 entries";
    case PLUGIN_INDEX_IO:
        return "check permissions and free space of the index directory and retry";
    default:
        return "pass the documented arguments: z23 discover describe plugin";
    }
}

static void pix_push_caps(struct json_value *obj, unsigned mask)
{
    struct json_value caps;
    json_init(&caps);
    json_set_array(&caps);
    for (unsigned i = 0; plugin_capability_name(i); i++) {
        struct json_value s;
        json_init(&s);
        if (mask & (1u << i)) {
            json_set_str(&s, plugin_capability_name(i));
            (void)json_push_back(&caps, &s);
        }
        json_free(&s);
    }
    (void)json_push_kv(obj, "capabilities", &caps);
    json_free(&caps);
}

static void pix_push_entry(struct json_value *obj,
                           const struct plugin_index_entry *e)
{
    (void)json_push_kv_str(obj, "name", e->name);
    (void)json_push_kv_str(obj, "version", e->version);
    (void)json_push_kv_int(obj, "interface_version", e->interface_version);
    pix_push_caps(obj, e->capabilities);
    (void)json_push_kv_str(obj, "root", e->root);
    (void)json_push_kv_str(obj, "publisher", e->publisher);
    (void)json_push_kv_int(obj, "timestamp", e->timestamp);
    (void)json_push_kv_str(obj, "entry", e->digest);
}

void zcl_native_handle_plugin_index_add(const struct zcl_command_request *request,
                                        struct zcl_command_reply *reply)
{
    struct plugin_index_publish pub = {0};
    struct plugin_index_entry entry;
    enum plugin_status cause = PLUGIN_OK;
    bool present = false;
    if (!request || !reply)
        return;
    pub.root = pix_str(request, "root");
    pub.manifest_path = pix_str(request, "manifest");
    pub.key_path = pix_str(request, "key");
    pub.dir = pix_str(request, "index");
    pub.timestamp = (int64_t)time(NULL);
    enum plugin_index_status st = plugin_index_publish(&pub, &entry, &present, &cause);
    if (st == PLUGIN_INDEX_SOURCE) {
        pix_refuse(reply, plugin_status_code(cause), plugin_status_next_action(cause),
                   "index_add", pub.manifest_path);
        return;
    }
    if (st != PLUGIN_INDEX_OK) {
        pix_refuse(reply, plugin_index_status_code(st), pix_next_action(st),
                   "index_add", pub.dir);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_index_add.v1");
    pix_push_entry(&reply->data, &entry);
    (void)json_push_kv_bool(&reply->data, "already_present", present);
    reply->error.mutated = !present;
}

static bool pix_caps(const struct zcl_command_request *request, unsigned *mask)
{
    const struct json_value *v = request->input ? json_get(request->input, "cap") : NULL;
    *mask = 0;
    if (!v || json_is_null(v))
        return true;
    if (v->type == JSON_STR) {
        const char *csv = json_get_str(v);
        while (*csv) {
            size_t len = strcspn(csv, ",");
            if (!len || !plugin_capability_add(csv, len, mask))
                return false;
            csv += len;
            if (*csv == ',' && csv[1] == '\0')
                return false;
            csv += (*csv == ',');
        }
        return true;
    }
    if (v->type != JSON_ARR)
        return false;
    for (size_t i = 0; i < json_size(v); i++) {
        const struct json_value *item = json_at(v, i);
        const char *s = item && item->type == JSON_STR ? json_get_str(item) : NULL;
        if (!s || !*s || !plugin_capability_add(s, strlen(s), mask))
            return false;
    }
    return true;
}

static void pix_push_report(struct json_value *data,
                            const struct plugin_index_report *rep)
{
    struct json_value rows, refused;
    json_init(&rows);
    json_init(&refused);
    json_set_array(&rows);
    json_set_array(&refused);
    for (size_t i = 0; i < rep->row_count; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        pix_push_entry(&row, &rep->rows[i].entry);
        (void)json_push_kv_str(&row, "publisher_status",
                               rep->rows[i].pinned ? "pinned" : "unpinned");
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    for (size_t i = 0; i < rep->refusal_count; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "file", rep->refusals[i].file);
        (void)json_push_kv_str(&row, "code", rep->refusals[i].code);
        (void)json_push_back(&refused, &row);
        json_free(&row);
    }
    (void)json_push_kv_int(data, "count", (int64_t)rep->row_count);
    (void)json_push_kv(data, "plugins", &rows);
    (void)json_push_kv(data, "refused", &refused);
    (void)json_push_kv_int(data, "scanned", (int64_t)rep->scanned);
    (void)json_push_kv_int(data, "duplicates", (int64_t)rep->duplicates);
    (void)json_push_kv_int(data, "superseded", (int64_t)rep->superseded);
    json_free(&rows);
    json_free(&refused);
}

void zcl_native_handle_plugin_search(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    struct plugin_index_query query = {0};
    struct plugin_index_report rep;
    if (!request || !reply)
        return;
    query.name = pix_str(request, "name");
    if (!pix_caps(request, &query.capabilities)) {
        pix_refuse(reply, "PLUGIN_INDEX_ARGUMENT",
                   "cap must name distinct capabilities from the plugin vocabulary",
                   "search", NULL);
        return;
    }
    const char *dir = pix_str(request, "index");
    enum plugin_index_status st = plugin_index_search(
        dir, pix_str(request, "publishers"), &query, &rep);
    if (st != PLUGIN_INDEX_OK) {
        pix_refuse(reply, plugin_index_status_code(st), pix_next_action(st),
                   "search", dir);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_search.v1");
    (void)json_push_kv_str(&reply->data, "note",
                           "listing only: nothing was fetched or installed; "
                           "pinned means the publisher key is in your list");
    pix_push_report(&reply->data, &rep);
    plugin_index_report_free(&rep);
}
