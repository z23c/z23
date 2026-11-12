/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "host_ops.h"
#include "json/json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { ERRORS_SHOWN = 5, PLUGINS_SHOWN = 8, SAVED_SHOWN = 2, LINE_SHOWN = 200, REPLY_BYTES = 16384,
       TEXT_BYTES = 1400, READ_MS = 15000, CONFIRM_MS = 75000 };
#define ERRORS_COMMAND "z23 ops logs --pattern=ERROR --since_secs=86400 --max_lines=5"
#define PLAN_COMMAND "z23 ops node restart"
#define PLUGINS_COMMAND "z23 plugin list"
#define CONFIRM_FORMAT "z23 ops node restart --input='{\"plan_id\":\"%s\",\"confirm\":true,\"wait_s\":60}'"
static const char *const action_words[] = {"errors", "plan", "confirm", "plugins"};

static bool plan_id_valid(const char *id)
{
    return strlen(id) == ZAPP_OPS_PLAN_ID && strspn(id, "0123456789abcdef") == ZAPP_OPS_PLAN_ID;
}
const struct zapp_fleet_host *zapp_ops_parse(const struct zapp_fleet_host *hosts, size_t count,
                                             const char *scope, enum zapp_ops_action *action,
                                             char plan_id[ZAPP_OPS_PLAN_ID + 1])
{
    char word[16], label[sizeof(hosts->label)];
    int used = 0;
    plan_id[0] = 0;
    if (!hosts || !scope || strlen(scope) > 80 || count > ZAPP_OPS_HOSTS ||
        sscanf(scope, "%15[a-z] %15[a-z0-9-]%n", word, label, &used) < 2) return NULL;
    size_t kind = 0;
    while (kind < sizeof(action_words) / sizeof(action_words[0]) && strcmp(word, action_words[kind])) kind++;
    const char *rest = scope + used;
    if (kind == sizeof(action_words) / sizeof(action_words[0])) return NULL;
    if (kind == ZAPP_OPS_CONFIRM) {
        if (*rest++ != ' ' || !plan_id_valid(rest)) return NULL;
        memcpy(plan_id, rest, ZAPP_OPS_PLAN_ID + 1);
    } else if (*rest) return NULL;
    for (size_t i = 0; i < count; i++)
        if (!strcmp(hosts[i].label, label)) { *action = (enum zapp_ops_action)kind; return &hosts[i]; }
    plan_id[0] = 0;
    return NULL;
}
/* Writes the reply object: text under "text" (with the action and plan id when given) or an error. */
static bool reply(const char *host, const char *action, const char *plan_id, const char *key,
                  const char *text, const char *ids, char *out, size_t cap)
{
    struct json_value root = {0};
    json_set_object(&root);
    bool ok = json_push_kv_str(&root, "host", host) &&
        (!action || json_push_kv_str(&root, "action", action)) &&
        (!plan_id || json_push_kv_str(&root, "plan_id", plan_id)) &&
        json_push_kv_str(&root, key, text) && (!ids || json_push_kv_str(&root, "ids", ids)) &&
        json_write(&root, out, cap) < cap;
    json_free(&root);
    return ok;
}
static void printable(char *dst, size_t cap, const char *src)
{
    size_t n = 0;
    for (; src[n] && n + 1 < cap && n < LINE_SHOWN; n++)
        dst[n] = (unsigned char)src[n] >= 0x20 && (unsigned char)src[n] < 0x7f ? src[n] : '?';
    dst[n] = 0;
}
/* The leaf's error message, or fallback when the output is not a leaf reply. */
static const char *leaf_error(const struct json_value *doc, const char *fallback)
{
    const char *message = json_get_str(json_get(json_get(doc, "error"), "message"));
    return message && message[0] && strlen(message) < 300 ? message : fallback;
}
static void errors_text(const struct json_value *data, char *text, size_t cap)
{
    const struct json_value *lines = json_get(data, "lines");
    size_t used = 0;
    text[0] = 0;
    for (size_t i = 0; i < json_size(lines) && i < ERRORS_SHOWN; i++) {
        char line[LINE_SHOWN + 1];
        printable(line, sizeof(line), json_get_str(json_at(lines, i)));
        int n = snprintf(text + used, cap - used, "%s%s", used ? "\n" : "", line);
        if (n < 0 || (size_t)n >= cap - used) break;
        used += (size_t)n;
    }
    if (!used) snprintf(text, cap, "No errors in the last 24 hours.");
}
static void plan_text(const char *host, const struct json_value *data, char *text, size_t cap)
{
    const struct json_value *height = json_get(data, "height_now"), *up = json_get(data, "uptime_s_now");
    char now[96] = "The node is not answering.";
    if (height && height->type == JSON_INT && up && up->type == JSON_INT)
        snprintf(now, sizeof(now), "It is at height %lld, running for %lld s.",
                 (long long)json_get_int(height), (long long)json_get_int(up));
    else if (height && height->type == JSON_INT)
        snprintf(now, sizeof(now), "It is at height %lld.", (long long)json_get_int(height));
    snprintf(text, cap, "Restart the z23 node on %s? %s Nothing changes until you confirm.", host, now);
}
static bool slot_state(const char *state)
{
    return state && (!strcmp(state, "ok") || !strcmp(state, "missing") || !strcmp(state, "unreadable") || !strcmp(state, "corrupt"));
}
static bool slot_text(const struct json_value *plugin, const char *id_key, const char *state_key, char *out, size_t cap)
{
    const char *id = json_get_str(json_get(plugin, id_key)), *state = json_get_str(json_get(plugin, state_key));
    if (!id || !slot_state(state)) return false;
    if (!strcmp(state, "ok")) {
        if (strlen(id) != 128 || strspn(id, "0123456789abcdef") != 128) return false;
        snprintf(out, cap, "%.12s (ok)", id);
    } else {
        if (id[0]) return false;
        snprintf(out, cap, "%s (%s)", !strcmp(state, "missing") ? "-" : "unknown", state);
    }
    return true;
}
static bool plugin_name(const struct json_value *plugin, const char **name)
{
    *name = json_get_str(json_get(plugin, "name"));
    size_t length = *name ? strlen(*name) : 0;
    if (!length || length > 32) return false;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)(*name)[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
    }
    return true;
}
static bool generations_valid(const struct json_value *plugin, const char *state)
{
    const struct json_value *generations = json_get(plugin, "generations");
    if (!generations || generations->type != JSON_ARR || (strcmp(state, "ok") && json_size(generations))) return false;
    for (size_t i = 0; i < json_size(generations); ++i) {
        const char *id = json_get_str(json_at(generations, i));
        if (!id || strlen(id) != 128 || strspn(id, "0123456789abcdef") != 128) return false;
    }
    return true;
}
static bool plugins_document_valid(const struct json_value *data, const struct json_value *plugins)
{
    const char *schema = json_get_str(json_get(data, "schema"));
    const struct json_value *count = json_get(data, "count");
    return schema && !strcmp(schema, "zcl.plugin_list.v1") && plugins && plugins->type == JSON_ARR &&
        count && count->type == JSON_INT && json_get_int(count) >= 0 &&
        (uint64_t)json_get_int(count) == (uint64_t)json_size(plugins);
}
static bool plugin_valid(const struct json_value *plugin, const char *store, const char **name,
                         char current[32], char last_good[32])
{
    return plugin_name(plugin, name) && slot_state(store) && generations_valid(plugin, store) &&
        slot_text(plugin, "current", "current_state", current, 32) &&
        slot_text(plugin, "last_good", "last_good_state", last_good, 32);
}
static bool saved_ids_text(const struct json_value *plugin, char *out, size_t cap)
{
    const char *current = json_get_str(json_get(plugin, "current"));
    const char *last_good = json_get_str(json_get(plugin, "last_good"));
    const struct json_value *generations = json_get(plugin, "generations");
    size_t used = 0, shown = 0, omitted = 0;
    out[0] = 0;
    for (size_t i = 0; i < json_size(generations); ++i) {
        const char *id = json_get_str(json_at(generations, i));
        if (!strcmp(id, current) || !strcmp(id, last_good)) continue;
        if (shown == SAVED_SHOWN) { omitted++; continue; }
        int n = snprintf(out + used, cap - used, "%s%.12s", shown ? ", " : "", id);
        if (n < 0 || (size_t)n >= cap - used) return false;
        used += (size_t)n;
        shown++;
    }
    if (omitted) {
        int n = snprintf(out + used, cap - used, " (+%zu more)", omitted);
        if (n < 0 || (size_t)n >= cap - used) return false;
    }
    return true;
}
static bool plugin_line(char *text, size_t cap, size_t *used, const char *name, const char *store,
                        const char *current, const char *last_good, const char *saved)
{
    int n = snprintf(text + *used, cap - *used, "\n%s\n current %s · last-good %s%s%s%s%s", name, current, last_good,
                     strcmp(store, "ok") ? " · store " : "", strcmp(store, "ok") ? store : "",
                     saved[0] ? "\n other saved IDs: " : "", saved);
    if (n < 0 || (size_t)n >= cap - *used) return false;
    *used += (size_t)n;
    return true;
}
static bool plugin_ids_line(char *text, size_t cap, size_t *used, const struct json_value *plugin, const char *name)
{
    const char *current = json_get_str(json_get(plugin, "current")), *current_state = json_get_str(json_get(plugin, "current_state"));
    const char *last_good = json_get_str(json_get(plugin, "last_good")), *last_state = json_get_str(json_get(plugin, "last_good_state"));
    int n = snprintf(text + *used, cap - *used, "\n%s\n current %s (%s)\n last-good %s (%s)", name,
                     !strcmp(current_state, "ok") ? current : "-", current_state,
                     !strcmp(last_state, "ok") ? last_good : "-", last_state);
    if (n < 0 || (size_t)n >= cap - *used) return false;
    *used += (size_t)n;
    return true;
}
static bool plugin_ids_text(const struct json_value *data, char *ids, size_t cap)
{
    const struct json_value *plugins = json_get(data, "plugins");
    if (!plugins_document_valid(data, plugins)) return false;
    size_t used = 0, total = json_size(plugins), shown = total < PLUGINS_SHOWN ? total : PLUGINS_SHOWN;
    for (size_t i = 0; i < total; ++i) {
        const struct json_value *plugin = json_at(plugins, i), *store_value = json_get(plugin, "generations_state");
        const char *name, *store = json_get_str(store_value);
        char current[32], last_good[32], saved[64];
        if (!plugin_valid(plugin, store, &name, current, last_good) ||
            !saved_ids_text(plugin, saved, sizeof(saved))) return false;
        if (i >= shown) continue;
        if (!plugin_ids_line(ids, cap, &used, plugin, name)) return false;
    }
    if (total > shown) {
        int n = snprintf(ids + used, cap - used, "\n%zu more plugins not copied.", total - shown);
        if (n < 0 || (size_t)n >= cap - used) return false;
    }
    return true;
}
static bool plugins_text(const struct json_value *data, char *text, size_t cap, char *ids, size_t ids_cap)
{
    const struct json_value *plugins = json_get(data, "plugins");
    if (!plugins_document_valid(data, plugins)) return false;
    int first = snprintf(text, cap, "Inventory scan only; signatures are not rechecked.");
    if (first < 0 || (size_t)first >= cap) return false;
    size_t used = (size_t)first, total = json_size(plugins), shown = total < PLUGINS_SHOWN ? total : PLUGINS_SHOWN;
    ids[0] = 0;
    if (!total) {
        int n = snprintf(text + used, cap - used, "\nNo plugins installed.");
        return n > 0 && (size_t)n < cap - used;
    }
    for (size_t i = 0; i < total; ++i) {
        const struct json_value *plugin = json_at(plugins, i), *store_value = json_get(plugin, "generations_state");
        const char *name, *store = json_get_str(store_value);
        char current[32], last_good[32], saved[64];
        if (!plugin_valid(plugin, store, &name, current, last_good) ||
            !saved_ids_text(plugin, saved, sizeof(saved))) return false;
        if (i >= shown) continue;
        if (!plugin_line(text, cap, &used, name, store, current, last_good, saved)) return false;
    }
    if (total > shown) {
        int n = snprintf(text + used, cap - used, "\n%zu more not shown.", total - shown);
        if (n < 0 || (size_t)n >= cap - used) return false;
    }
    return plugin_ids_text(data, ids, ids_cap);
}
/* Turns a leaf reply into the text to show; false puts the leaf's refusal in text instead. */
static bool leaf_text(enum zapp_ops_action action, const char *host, const struct json_value *doc,
                      char *text, size_t cap, char *ids, size_t ids_cap, char plan[ZAPP_OPS_PLAN_ID + 1])
{
    const struct json_value *data = json_get(doc, "data");
    plan[0] = 0;
    if (!json_get_bool(json_get(doc, "ok")) || !data) {
        snprintf(text, cap, "%s", leaf_error(doc, "The host refused the request."));
        return false;
    }
    if (action == ZAPP_OPS_ERRORS) errors_text(data, text, cap);
    else if (action == ZAPP_OPS_PLUGINS) {
        if (!plugins_text(data, text, cap, ids, ids_cap)) {
            snprintf(text, cap, "The host's plugin inventory was not understood.");
            return false;
        }
    } else if (action == ZAPP_OPS_CONFIRM) {
        const char *note = json_get_str(json_get(data, "note"));
        snprintf(text, cap, "%s", note && note[0] && strlen(note) < 200 ? note : "Restart requested.");
    } else {
        snprintf(plan, ZAPP_OPS_PLAN_ID + 1, "%s", json_get_str(json_get(data, "plan_id")));
        if (plan_id_valid(plan)) plan_text(host, data, text, cap);
        else { plan[0] = 0; snprintf(text, cap, "The host sent no restart plan."); }
    }
    return action != ZAPP_OPS_PLAN || plan[0];
}
/* Spends the host's stored plan: true only for the id it holds, issued within its lifetime. */
static bool spend_plan(struct zapp_ops *ops, size_t slot, const char *id, int64_t now)
{
    bool live = ops->plans[slot].id[0] && !strcmp(ops->plans[slot].id, id) &&
        now >= ops->plans[slot].issued && now - ops->plans[slot].issued <= ZAPP_OPS_PLAN_TTL_S;
    memset(&ops->plans[slot], 0, sizeof(ops->plans[slot]));
    return live;
}
static bool run(struct zapp_ops *ops, const struct zapp_fleet_host *host, enum zapp_ops_action action,
                const char *plan_id, char *text, size_t cap, char *ids, size_t ids_cap, char plan[ZAPP_OPS_PLAN_ID + 1])
{
    char command[160], *raw = malloc(REPLY_BYTES);
    struct json_value doc = {0};
    int n = action == ZAPP_OPS_ERRORS ? snprintf(command, sizeof(command), "%s", ERRORS_COMMAND) :
        action == ZAPP_OPS_PLUGINS ? snprintf(command, sizeof(command), "%s", PLUGINS_COMMAND) :
        action == ZAPP_OPS_PLAN ? snprintf(command, sizeof(command), "%s", PLAN_COMMAND) :
        snprintf(command, sizeof(command), CONFIRM_FORMAT, plan_id);
    bool ran = raw && n > 0 && (size_t)n < sizeof(command) && ops->exec &&
        ops->exec(host, command, action == ZAPP_OPS_CONFIRM ? CONFIRM_MS : READ_MS, raw, REPLY_BYTES, ops->ctx);
    bool ok = false;
    if (!ran) snprintf(text, cap, "The host did not answer.");
    else if (action == ZAPP_OPS_PLUGINS && strlen(raw) >= REPLY_BYTES - 1)
        snprintf(text, cap, "The plugin inventory is too large to read safely.");
    else if (!json_read(&doc, raw, strlen(raw))) snprintf(text, cap, "The host's reply could not be read.");
    else ok = leaf_text(action, host->label, &doc, text, cap, ids, ids_cap, plan);
    json_cleanse_strings(&doc); json_free(&doc); free(raw);
    return ok;
}
bool zapp_ops_handle(struct zapp_ops *ops, const struct zapp_fleet_host *hosts, size_t count,
                     const char *scope, int64_t now, char *out, size_t cap)
{
    enum zapp_ops_action action = ZAPP_OPS_ERRORS;
    char plan_id[ZAPP_OPS_PLAN_ID + 1], plan[ZAPP_OPS_PLAN_ID + 1] = "", text[TEXT_BYTES], ids[4096] = "";
    const struct zapp_fleet_host *host = zapp_ops_parse(hosts, count, scope, &action, plan_id);
    if (!host) return reply("", NULL, NULL, "error", "That request is not allowed.", NULL, out, cap);
    size_t slot = (size_t)(host - hosts);
    bool ok = action != ZAPP_OPS_CONFIRM || spend_plan(ops, slot, plan_id, now);
    if (!ok) snprintf(text, sizeof(text), "No current restart plan. Plan the restart again.");
    else ok = run(ops, host, action, plan_id, text, sizeof(text), ids, sizeof(ids), plan);
    if (ok && action == ZAPP_OPS_PLAN) {
        memcpy(ops->plans[slot].id, plan, sizeof(plan));
        ops->plans[slot].issued = now;
    }
    return reply(host->label, ok ? action_words[action] : NULL, ok && plan[0] ? plan : NULL,
                 ok ? "text" : "error", text, ok && action == ZAPP_OPS_PLUGINS ? ids : NULL, out, cap);
}
