/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: plugin.pack, plugin.keygen, plugin.publisher, plugin.install, plugin.list, plugin.status, plugin.switch, plugin.rollback,
 *          plugin.run and plugin.call — the signed plugin store under ~/.z23/plugins and the
 *          confined supervisor (run) and one-shot runner (call) for one installed plugin. Every refusal
 *          carries a stable PLUGIN_* code and the command that resolves it.
 *          The daemon is not contacted. */

#include "base/safe_alloc.h"
#include "command/lab.h"
#include "command/lab_priv.h"
#include "command/native_command.h"
#include "native_plugin_common.h"

#include "json/json.h"
#include "plugin/plugin_pack.h"
#include "plugin/plugin_run.h"
#include "plugin/plugin_store.h"

#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void plg_refuse(struct zcl_command_reply *reply, enum plugin_status st,
                       const char *what, const char *evidence)
{
    char message[192];
    (void)snprintf(message, sizeof(message), "plugin %s refused: %s", what,
                   plugin_status_code(st));
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           st == PLUGIN_ERR_IO ? ZCL_COMMAND_EXIT_FAILED
                                               : ZCL_COMMAND_EXIT_INVALID,
                           plugin_status_code(st), what, false, false, message,
                           evidence ? evidence : "");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", plugin_status_next_action(st));
    reply->error.human_action_required = true;
}

const char *plg_str(const struct zcl_command_request *request,
                           const char *key)
{
    const struct json_value *v = request->input ? json_get(request->input, key)
                                                : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static bool plg_root(char *out, size_t cap)
{
    const char *home = getenv("HOME");
    if (!home || home[0] != '/')
        return false;
    int n = snprintf(out, cap, "%s/.z23/plugins", home);
    return n > 0 && (size_t)n < cap;
}

static bool plg_begin(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply, const char *what,
                      char *root, size_t cap)
{
    if (!request || !reply)
        return false;
    if (!plg_root(root, cap)) {
        plg_refuse(reply, PLUGIN_ERR_ARGUMENT, what, "HOME is not absolute");
        return false;
    }
    return true;
}

void plg_push_capabilities(struct json_value *obj, unsigned mask)
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

/* Capabilities arrive as a JSON array of names or one comma-separated string. */
static bool plg_cap_csv(const char *csv, unsigned *mask)
{
    while (*csv) {
        size_t len = strcspn(csv, ",");
        if (len == 0 || !plugin_capability_add(csv, len, mask))
            return false;
        if (csv[len] == ',' && csv[len + 1] == '\0')
            return false;
        csv += len + (csv[len] == ',');
    }
    return true;
}

bool plg_capabilities(const struct zcl_command_request *request, unsigned *mask)
{
    const struct json_value *v = request->input ? json_get(request->input, "cap") : NULL;
    *mask = 0;
    if (!v || json_is_null(v))
        return true;
    if (v->type == JSON_STR)
        return plg_cap_csv(json_get_str(v), mask);
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

/* The follow-up input is built as JSON so any path stays one string value. */
static void plg_next_install(struct zcl_command_reply *reply, const char *manifest)
{
    struct json_value follow_up;
    json_init(&follow_up);
    json_set_object(&follow_up);
    if (json_push_kv_str(&follow_up, "manifest", manifest)) {
        size_t need = json_write(&follow_up, NULL, 0) + 1;
        char *text = zcl_malloc(need, "plugin.pack.next");
        if (text && json_write(&follow_up, text, need) < need)
            (void)zcl_command_reply_add_next(reply, "plugin.install", text,
                                             "install the packed plugin after adding its key as a publisher key");
        free(text);
    }
    json_free(&follow_up);
}

/* The interface version from a JSON integer or its decimal string; absent
 * means 1. false = not 1 or 2. */
static bool plg_interface(const struct zcl_command_request *request, int *out)
{
    const struct json_value *v = request->input ? json_get(request->input, "interface") : NULL;
    int64_t n = 1;
    if (v && v->type == JSON_INT)
        n = json_get_int(v);
    else if (v && v->type == JSON_STR)
        n = strcmp(json_get_str(v), "1") == 0 ? 1 : strcmp(json_get_str(v), "2") == 0 ? 2 : 0;
    else if (v && !json_is_null(v))
        n = 0;
    *out = (int)n;
    return n == 1 || n == 2;
}

void zcl_native_handle_plugin_pack(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    struct plugin_pack_request pack = {0};
    struct plugin_pack_result result;
    if (!request || !reply)
        return;
    pack.exe_path = plg_str(request, "exe");
    pack.name = plg_str(request, "name");
    pack.version = plg_str(request, "version");
    pack.key_path = plg_str(request, "key");
    pack.out_dir = plg_str(request, "dir");
    if (!plg_interface(request, &pack.interface_version)) {
        plg_refuse(reply, PLUGIN_ERR_ARGUMENT, "pack", "interface must be 1 or 2");
        return;
    }
    if (!plg_capabilities(request, &pack.capabilities)) {
        plg_refuse(reply, PLUGIN_ERR_ARGUMENT, "pack",
                   "cap must name distinct capabilities from the plugin vocabulary");
        return;
    }
    enum plugin_status st = plugin_pack(&pack, &result);
    if (st != PLUGIN_OK) {
        bool key_fault = st >= PLUGIN_ERR_KEY_MISSING && st <= PLUGIN_ERR_KEY_MALFORMED;
        plg_refuse(reply, st, "pack", key_fault ? pack.key_path : pack.exe_path);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_pack.v1");
    (void)json_push_kv_str(&reply->data, "name", pack.name);
    (void)json_push_kv_str(&reply->data, "version", pack.version);
    (void)json_push_kv_int(&reply->data, "interface_version", pack.interface_version);
    (void)json_push_kv_str(&reply->data, "generation", result.generation);
    (void)json_push_kv_str(&reply->data, "public_key", result.public_key);
    (void)json_push_kv_str(&reply->data, "manifest", result.manifest_path);
    plg_push_capabilities(&reply->data, pack.capabilities);
    reply->error.mutated = true;
    plg_next_install(reply, result.manifest_path);
}

void zcl_native_handle_plugin_keygen(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    char public_key[PLUGIN_HEX_PUBLIC_KEY + 1];
    if (!request || !reply)
        return;
    const char *key = plg_str(request, "key");
    enum plugin_status st = plugin_keygen(key, public_key);
    if (st != PLUGIN_OK) {
        plg_refuse(reply, st, "keygen", key);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_keygen.v1");
    (void)json_push_kv_str(&reply->data, "public_key", public_key);
    (void)json_push_kv_str(&reply->data, "key_file", key);
    reply->error.mutated = true;
    char input[128];
    (void)snprintf(input, sizeof(input), "{\"key\":\"%s\"}", public_key);
    (void)zcl_command_reply_add_next(reply, "plugin.publisher", input,
                                     "add this publisher key so z23 verifies its plugins before installing them");
}

void zcl_native_handle_plugin_publisher(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    char root[PATH_MAX];
    if (!plg_begin(request, reply, "publisher", root, sizeof(root)))
        return;
    const char *key = plg_str(request, "key");
    int already = 0;
    enum plugin_status st = plugin_store_add_key(root, key, &already);
    if (st != PLUGIN_OK) {
        plg_refuse(reply, st, "publisher", key ? key : "");
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_publisher.v1");
    (void)json_push_kv_str(&reply->data, "public_key", key);
    (void)json_push_kv_bool(&reply->data, "already_listed", already != 0);
    reply->error.mutated = already == 0;
}

void zcl_native_handle_plugin_install(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    char root[PATH_MAX];
    if (!plg_begin(request, reply, "install", root, sizeof(root)))
        return;
    const char *path = plg_str(request, "manifest");
    struct plugin_manifest m;
    int present = 0;
    enum plugin_status st = plugin_store_install(root, path, &m, &present);
    if (st != PLUGIN_OK) {
        plg_refuse(reply, st, "install", path);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_install.v1");
    (void)json_push_kv_str(&reply->data, "name", m.name);
    (void)json_push_kv_str(&reply->data, "version", m.version);
    (void)json_push_kv_int(&reply->data, "interface_version", m.interface_version);
    (void)json_push_kv_str(&reply->data, "generation", m.generation);
    (void)json_push_kv_bool(&reply->data, "already_present", present != 0);
    plg_push_capabilities(&reply->data, m.capabilities);
    reply->error.mutated = present == 0;
    char input[256];
    (void)snprintf(input, sizeof(input), "{\"name\":\"%s\",\"generation\":\"%s\"}",
                   m.name, m.generation);
    (void)zcl_command_reply_add_next(reply, "plugin.switch", input,
                                     "make this generation current");
}

static void plg_push_info(struct json_value *plugins, const struct plugin_info *info)
{
    struct json_value row, gens;
    json_init(&row);
    json_init(&gens);
    json_set_object(&row);
    json_set_array(&gens);
    (void)json_push_kv_str(&row, "name", info->name);
    (void)json_push_kv_str(&row, "current", info->current);
    (void)json_push_kv_str(&row, "last_good", info->last_good);
    (void)json_push_kv_str(&row, "current_state", plugin_slot_state_name(info->current_state));
    (void)json_push_kv_str(&row, "last_good_state",
                           plugin_slot_state_name(info->last_good_state));
    (void)json_push_kv_str(&row, "generations_state",
                           plugin_slot_state_name(info->generations_state));
    for (size_t g = 0; g < info->generation_count; g++) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, info->generations[g]);
        (void)json_push_back(&gens, &s);
        json_free(&s);
    }
    (void)json_push_kv(&row, "generations", &gens);
    (void)json_push_back(plugins, &row);
    json_free(&gens);
    json_free(&row);
}

void zcl_native_handle_plugin_list(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    char root[PATH_MAX];
    if (!plg_begin(request, reply, "list", root, sizeof(root)))
        return;
    struct plugin_info *infos = NULL;
    size_t count = 0;
    enum plugin_status st = plugin_store_list(root, &infos, &count);
    if (st != PLUGIN_OK) {
        plg_refuse(reply, st, "list", root);
        return;
    }
    struct json_value plugins;
    json_init(&plugins);
    json_set_array(&plugins);
    for (size_t i = 0; i < count; i++)
        plg_push_info(&plugins, &infos[i]);
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_list.v1");
    (void)json_push_kv_int(&reply->data, "count", (int64_t)count);
    (void)json_push_kv(&reply->data, "plugins", &plugins);
    json_free(&plugins);
    plugin_store_list_free(infos, count);
}

/* The first part of a plugin's stored state that could not be read, as
 * "generations unreadable" or "current corrupt"; false when every part read. A
 * missing link or directory is a fact (nothing set, nothing stored). */
static bool plg_state_fault(const struct plugin_info *info, char *out, size_t cap)
{
    static const char *const part[] = { "generations", "current", "last-good" };
    const enum plugin_slot_state state[] = { info->generations_state, info->current_state,
                                             info->last_good_state };
    for (size_t i = 0; i < 3; i++)
        if (state[i] == PLUGIN_SLOT_UNREADABLE || state[i] == PLUGIN_SLOT_CORRUPT) {
            (void)snprintf(out, cap, "%s: %s %s", info->name, part[i],
                           plugin_slot_state_name(state[i]));
            return true;
        }
    return false;
}

/* Read-only: one store scan, no signature verify, no executable hash. The
 * reply says so in "work" so an operator can see what the call cost. */
void zcl_native_handle_plugin_status(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    char root[PATH_MAX];
    if (!plg_begin(request, reply, "status", root, sizeof(root)))
        return;
    const char *name = plg_str(request, "name");
    if (!name || !name[0]) {
        plg_refuse(reply, PLUGIN_ERR_ARGUMENT, "status", "name is required");
        return;
    }
    struct plugin_info *infos = NULL;
    size_t count = 0;
    enum plugin_status st = plugin_store_list(root, &infos, &count);
    if (st != PLUGIN_OK) {
        plg_refuse(reply, st, "status", root);
        return;
    }
    const struct plugin_info *hit = NULL;
    for (size_t i = 0; i < count && !hit; i++)
        if (strcmp(infos[i].name, name) == 0)
            hit = &infos[i];
    if (!hit) {
        plg_refuse(reply, PLUGIN_ERR_NOT_INSTALLED, "status", name);
        plugin_store_list_free(infos, count);
        return;
    }
    char fault[PLUGIN_NAME_MAX + 64];
    if (plg_state_fault(hit, fault, sizeof(fault))) {
        plg_refuse(reply, PLUGIN_ERR_IO, "status", fault);
        plugin_store_list_free(infos, count);
        return;
    }
    struct json_value work;
    json_init(&work);
    json_set_object(&work);
    (void)json_push_kv_int(&work, "scanned", (int64_t)count);
    (void)json_push_kv_int(&work, "verified", 0);
    (void)json_push_kv_int(&work, "hashed", 0);
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_status.v1");
    (void)json_push_kv_str(&reply->data, "name", hit->name);
    (void)json_push_kv_str(&reply->data, "current", hit->current);
    (void)json_push_kv_str(&reply->data, "last_good", hit->last_good);
    (void)json_push_kv_int(&reply->data, "generations",
                           (int64_t)hit->generation_count);
    (void)json_push_kv_str(&reply->data, "current_state",
                           plugin_slot_state_name(hit->current_state));
    (void)json_push_kv_str(&reply->data, "last_good_state",
                           plugin_slot_state_name(hit->last_good_state));
    (void)json_push_kv_str(&reply->data, "generations_state",
                           plugin_slot_state_name(hit->generations_state));
    (void)json_push_kv(&reply->data, "work", &work);
    json_free(&work);
    plugin_store_list_free(infos, count);
}

void zcl_native_handle_plugin_switch(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    char root[PATH_MAX];
    if (!plg_begin(request, reply, "switch", root, sizeof(root)))
        return;
    const char *name = plg_str(request, "name");
    const char *generation = plg_str(request, "generation");
    enum plugin_status st = plugin_store_switch(root, name, generation);
    if (st != PLUGIN_OK) {
        plg_refuse(reply, st, "switch", name);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_switch.v1");
    (void)json_push_kv_str(&reply->data, "name", name);
    (void)json_push_kv_str(&reply->data, "current", generation);
    reply->error.mutated = true;
}

void zcl_native_handle_plugin_rollback(const struct zcl_command_request *request,
                                       struct zcl_command_reply *reply)
{
    char root[PATH_MAX], restored[PLUGIN_HEX_SHA3_512 + 1];
    if (!plg_begin(request, reply, "rollback", root, sizeof(root)))
        return;
    const char *name = plg_str(request, "name");
    enum plugin_status st = plugin_store_rollback(root, name, restored);
    if (st != PLUGIN_OK) {
        plg_refuse(reply, st, "rollback", name);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_rollback.v1");
    (void)json_push_kv_str(&reply->data, "name", name);
    (void)json_push_kv_str(&reply->data, "current", restored);
    reply->error.mutated = true;
}

static volatile sig_atomic_t g_plg_stop;
static volatile sig_atomic_t g_plg_reload;

#if defined(_WIN32)
/* No confined plugin process exists here; plugin_run_open refuses first. */
struct plg_handlers {
    int unused;
};

static void plg_signals_install(struct plg_handlers *saved)
{
    (void)saved;
    g_plg_stop = 0;
    g_plg_reload = 0;
}

static void plg_signals_restore(const struct plg_handlers *saved)
{
    (void)saved;
}
#else
static void plg_on_stop(int sig)
{
    (void)sig;
    g_plg_stop = 1;
}

static void plg_on_reload(int sig)
{
    (void)sig;
    g_plg_reload = 1;
}

struct plg_handlers {
    struct sigaction term, intr, hup, chld;
};

static void plg_signals_install(struct plg_handlers *saved)
{
    struct sigaction stop = {.sa_handler = plg_on_stop};
    struct sigaction reload = {.sa_handler = plg_on_reload};
    sigemptyset(&stop.sa_mask);
    sigemptyset(&reload.sa_mask);
    g_plg_stop = 0;
    g_plg_reload = 0;
    sigaction(SIGTERM, &stop, &saved->term);
    sigaction(SIGINT, &stop, &saved->intr);
    sigaction(SIGHUP, &reload, &saved->hup);
    /* An ignored SIGCHLD would discard the plugin's exit status. */
    struct sigaction dfl = {.sa_handler = SIG_DFL};
    sigemptyset(&dfl.sa_mask);
    sigaction(SIGCHLD, &dfl, &saved->chld);
}

static void plg_signals_restore(const struct plg_handlers *saved)
{
    sigaction(SIGTERM, &saved->term, NULL);
    sigaction(SIGINT, &saved->intr, NULL);
    sigaction(SIGHUP, &saved->hup, NULL);
    sigaction(SIGCHLD, &saved->chld, NULL);
}
#endif

/* The run seconds, from a JSON integer or its decimal string; 0 means until
 * stopped. false = malformed. */
static bool plg_seconds(const struct zcl_command_request *request, uint32_t *out)
{
    const struct json_value *v = request->input ? json_get(request->input, "seconds") : NULL;
    int64_t n = 0;
    *out = 0;
    if (!v || json_is_null(v))
        return true;
    if (v->type == JSON_INT) {
        n = json_get_int(v);
    } else if (v->type == JSON_STR) {
        char *end = NULL;
        n = strtoll(json_get_str(v), &end, 10);
        if (!end || *end != '\0' || end == json_get_str(v))
            return false;
    } else {
        return false;
    }
    if (n < 0 || n > 86400)
        return false;
    *out = (uint32_t)n;
    return true;
}

static void plg_run_refuse_as(struct zcl_command_reply *reply, enum plugin_run_status st,
                           enum plugin_status store, const char *what, const char *name)
{
    if (st == PLUGIN_RUN_ERR_STORE) {
        plg_refuse(reply, store, what, name);
        return;
    }
    char message[192];
    (void)snprintf(message, sizeof(message), "plugin %s refused: %s", what,
                   plugin_run_status_code(st));
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                           plugin_run_status_code(st), what, false, false, message,
                           name ? name : "");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action), "%s",
                   plugin_run_status_next_action(st));
    reply->error.human_action_required = true;
}

static void plg_run_refuse(struct zcl_command_reply *reply, enum plugin_run_status st,
                           enum plugin_status store, const char *name)
{
    plg_run_refuse_as(reply, st, store, "run", name);
}

static void plg_run_report(struct zcl_command_reply *reply, const char *name,
                           const struct plugin_run_info *info, bool stopped)
{
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_run.v1");
    (void)json_push_kv_str(&reply->data, "name", name);
    (void)json_push_kv_str(&reply->data, "generation", info->generation);
    (void)json_push_kv_bool(&reply->data, "stopped", stopped);
    (void)json_push_kv_int(&reply->data, "restarts", info->restarts);
    (void)json_push_kv_int(&reply->data, "pings_ok", (int64_t)info->pings_ok);
    (void)json_push_kv_bool(&reply->data, "fell_back", info->fell_back);
    (void)json_push_kv_str(&reply->data, "detail", info->detail);
    reply->error.mutated = info->fell_back;
}

void zcl_native_handle_plugin_run(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    char root[PATH_MAX];
    uint32_t seconds = 0;
    if (!plg_begin(request, reply, "run", root, sizeof(root)))
        return;
    const char *name = plg_str(request, "name");
    struct plugin_run_options options = {.root = root, .name = name, .log_to_stderr = true};
    struct plugin_run *run = NULL;
    enum plugin_status store = PLUGIN_OK;
    if (!plg_seconds(request, &seconds)) {
        plg_refuse(reply, PLUGIN_ERR_ARGUMENT, "run", "seconds must be 0 to 86400");
        return;
    }
    enum plugin_run_status st = plugin_run_open(&options, &run, &store);
    if (st != PLUGIN_RUN_OK) {
        plg_run_refuse(reply, st, store, name);
        return;
    }
    struct plg_handlers saved;
    plg_signals_install(&saved);
    st = plugin_run_loop(run, &g_plg_stop, &g_plg_reload, seconds * 1000u);
    plg_signals_restore(&saved);
    struct plugin_run_info info;
    plugin_run_info_get(run, &info);
    plugin_run_close(run);
    if (st != PLUGIN_RUN_OK) {
        bool named = st == PLUGIN_RUN_ERR_SPAWN || st == PLUGIN_RUN_ERR_CAPABILITY;
        plg_run_refuse(reply, named ? st : PLUGIN_RUN_ERR_FAILED, PLUGIN_OK, info.detail);
        return;
    }
    plg_run_report(reply, name, &info, true);
}

/* ── plugin.call: one-shot interface 2 ─────────────────────────────── */

struct plg_call_in {
    const char *name, *stdin_data;
    const char *args[LAB_ARGS_MAX];
    size_t n_args;
    uint32_t timeout_ms;
};

static bool plg_call_input(const struct zcl_command_request *request, struct plg_call_in *in)
{
    const struct json_value *a = request->input ? json_get(request->input, "args") : NULL;
    memset(in, 0, sizeof(*in));
    in->name = plg_str(request, "name");
    in->stdin_data = plg_str(request, "stdin");
    if (a && (a->type != JSON_ARR || a->num_children > LAB_ARGS_MAX))
        return false;
    for (size_t i = 0; a && i < a->num_children; i++) {
        if (a->children[i].type != JSON_STR)
            return false;
        in->args[in->n_args++] = json_get_str(&a->children[i]);
    }
    return in->name && lab_in_uint(request, "timeout_ms", LAB_TIMEOUT_DEFAULT_MS,
                                   LAB_TIMEOUT_MAX_MS, &in->timeout_ms) &&
           (!in->stdin_data || strlen(in->stdin_data) <= LAB_STDIN_MAX);
}

#if defined(__linux__)
static void plg_call_report(struct zcl_command_reply *reply, const struct plugin_manifest *m,
                            const struct lab_proc *proc)
{
    struct json_value run;
    json_init(&run);
    json_set_object(&reply->data);
    if (!json_push_kv_str(&reply->data, "schema", "zcl.plugin_call.v1") ||
        !json_push_kv_str(&reply->data, "name", m->name) ||
        !json_push_kv_str(&reply->data, "version", m->version) ||
        !json_push_kv_str(&reply->data, "sha3_512", m->exe_sha3) ||
        !json_push_kv_str(&reply->data, "generation", m->generation) ||
        !json_push_kv_int(&reply->data, "elapsed_ms", proc->wall_us / 1000) ||
        !lab_json_run(&run, proc, true, NULL) || !json_push_kv(&reply->data, "run", &run))
        plg_run_refuse_as(reply, PLUGIN_RUN_ERR_FAILED, PLUGIN_OK, "call", m->name);
    json_free(&run);
}

/* Run the verified executable once through the lab's confined runner: private
 * workdir, no network, no fork. Declared capabilities grant nothing more. */
static void plg_call_run(struct zcl_command_reply *reply, const struct plg_call_in *in,
                         const struct plugin_manifest *m, const char *exe)
{
    struct lab_dirs dirs;
    struct lab_proc proc;
    struct lab_inputs lab = {
        .stdin_data = in->stdin_data ? in->stdin_data : "",
        .stdin_len = in->stdin_data ? strlen(in->stdin_data) : 0,
        .args = in->args, .n_args = in->n_args,
        .timeout_ms = in->timeout_ms, .mem_mb = LAB_MEM_DEFAULT_MB,
    };
    if (lab_dirs_open(&dirs) != LAB_OK) {
        plg_refuse(reply, PLUGIN_ERR_IO, "call", "the lab state directory could not be prepared");
    } else if (!lab_confinement_available()) {
        plg_run_refuse_as(reply, PLUGIN_RUN_ERR_SANDBOX, PLUGIN_OK, "call", m->name);
    } else if (!lab_proc_init(&proc)) {
        plg_run_refuse_as(reply, PLUGIN_RUN_ERR_FAILED, PLUGIN_OK, "call", "allocation failed");
    } else {
        lab_run_binary(&dirs, exe, false, &lab, &proc);
        if (proc.launch == LAB_LAUNCHED)
            plg_call_report(reply, m, &proc);
        else
            plg_run_refuse_as(reply, proc.launch == LAB_LAUNCH_UNCONFINED
                                         ? PLUGIN_RUN_ERR_SANDBOX : PLUGIN_RUN_ERR_SPAWN,
                              PLUGIN_OK, "call", proc.detail);
        lab_proc_free(&proc);
    }
}

static void plg_call_current(const char *root, const struct plg_call_in *in,
                             struct zcl_command_reply *reply)
{
    char exe[PATH_MAX];
    struct plugin_manifest m;
    enum plugin_status st = plugin_store_current(root, in->name, &m, exe, sizeof(exe));
    if (st == PLUGIN_OK && m.interface_version != 2)
        st = PLUGIN_ERR_INTERFACE;
    if (st != PLUGIN_OK)
        plg_refuse(reply, st, "call", in->name);
    else
        plg_call_run(reply, in, &m, exe);
}
#endif


void zcl_native_handle_plugin_call(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    char root[PATH_MAX];
    struct plg_call_in in;
    if (!plg_begin(request, reply, "call", root, sizeof(root)))
        return;
    if (!plg_call_input(request, &in))
        plg_refuse(reply, PLUGIN_ERR_ARGUMENT, "call",
                   "name is required; timeout_ms is 1..60000, args at most 32 strings, "
                   "stdin at most 65536 bytes");
#if !defined(__linux__)
    else
        plg_run_refuse_as(reply, PLUGIN_RUN_ERR_PLATFORM, PLUGIN_OK, "call", in.name);
#else
    else
        plg_call_current(root, &in, reply);
#endif
}
