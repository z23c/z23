/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the `dev` command tree's pure input and interrupt policy —
 * request file-list confinement, drive cursor parsing, which cycle events
 * interrupt `dev drive`, and the test-group / generation / failure-id name
 * grammars — split out of native_dev_command.c so the HOT_FORK story
 * native-dev-input-and-interrupt-policy.v1 compiles this small file
 * instead of the whole command shell. Deterministic and effect-free: reads
 * caller-owned JSON and strings, writes only caller buffers, owns no
 * file-scope state. Behaviour and build-mode availability are unchanged
 * from the former static copies in native_dev_command.c. */

#include "command/native_dev_input_policy.h"

#include "dev_failure_store.h"
#include "devloop.h"

#include <stdio.h>
#include <string.h>

bool zcl_dev_request_files(const struct json_value *input,
                           bool allow_empty, const char **files,
                           size_t *count, char *why, size_t why_size)
{
    const struct json_value *array = json_get(input, "files");
    *count = 0;
    if (!array || array->type == JSON_NULL)
        return allow_empty;
    if (array->type != JSON_ARR ||
        (!allow_empty && array->num_children == 0) ||
        array->num_children > ZCL_DEVLOOP_MAX_FILES) {
        (void)snprintf(why, why_size,
                       "files must be a bounded string array%s",
                       allow_empty ? "" : " with at least one item");
        return false;
    }
    for (size_t i = 0; i < array->num_children; i++) {
        const struct json_value *item = &array->children[i];
        const char *path = json_get_str(item);
        if (item->type != JSON_STR || !path || !path[0] ||
            strlen(path) >= ZCL_DEVLOOP_PATH_MAX || path[0] == '/' ||
            strstr(path, "..")) {
            (void)snprintf(why, why_size,
                           "files[%zu] must be a confined relative path", i);
            return false;
        }
        files[i] = path;
    }
    *count = array->num_children;
    return true;
}

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
bool zcl_dev_drive_input_int(const struct json_value *input,
                             const char *key, int64_t fallback,
                             int64_t *out)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    if (!v || v->type == JSON_NULL) {
        *out = fallback;
        return true;
    }
    if (v->type != JSON_INT)
        return false;
    *out = json_get_int(v);
    return true;
}
#endif

#ifdef ZCL_DEV_BUILD
bool zcl_dev_event_interrupting(const struct json_value *cycle)
{
    const char *phase = cycle && cycle->type == JSON_OBJ
        ? json_get_str(json_get(cycle, "phase")) : NULL;
    const char *status = cycle && cycle->type == JSON_OBJ
        ? json_get_str(json_get(cycle, "status")) : NULL;
    return (phase && (strcmp(phase, "STORY_RED") == 0 ||
                      strcmp(phase, "COMPILE_RED") == 0 ||
                      strcmp(phase, "FOCUSED_RED") == 0)) ||
           (status && (strcmp(status, "story_red") == 0 ||
                       strcmp(status, "compile_red") == 0 ||
                       strcmp(status, "focused_red") == 0 ||
                       strcmp(status, "rejected") == 0));
}

bool zcl_dev_group_valid(const char *group)
{
    return group && group[0] && strlen(group) < 128 &&
        strspn(group,
               "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") ==
            strlen(group);
}

bool zcl_dev_generation_name_valid(const char *name)
{
    if (!name || strchr(name, '/') || strlen(name) >= 96)
        return false;
    const char *hex = NULL;
    if (strncmp(name, "gen-", 4) == 0)
        hex = name + 4;
    else if (strncmp(name, "legacy-", 7) == 0)
        hex = name + 7;
    if (!hex || strlen(hex) != 64)
        return false;
    return strspn(hex, "0123456789abcdef") == 64;
}
#endif

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
bool zcl_dev_failure_id_valid(const char *failure_id)
{
    if (!failure_id || strlen(failure_id) != ZCL_DEV_FAILURE_HEX_LEN)
        return false;
    return strspn(failure_id, "0123456789abcdef") ==
           ZCL_DEV_FAILURE_HEX_LEN;
}
#endif
