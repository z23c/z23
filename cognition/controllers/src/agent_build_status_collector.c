/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: collect optional repository tool status without inventing proof. */

#include "controllers/agent_build_status_collector.h"

#include "json/json.h"
#include "util/spawn.h"

#include <stdio.h>
#include <string.h>

void agent_collect_optional_status(struct json_value *out,
                                   const char *command,
                                   const char *schema)
{
    char buf[65536];
    char cmdcopy[1024];
    const char *argv[64];
    size_t argc = 0;
    buf[0] = '\0';
    if (snprintf(cmdcopy, sizeof(cmdcopy), "%s", command ? command : "")
            < (int)sizeof(cmdcopy))
        argc = zcl_argv_split(cmdcopy, argv, 64);
    int rc = argc ? zcl_spawn_capture(argv, buf, sizeof(buf), 30000) : -1;
    size_t used = strlen(buf);

    struct json_value parsed = {0};
    if (argc && json_read(&parsed, buf, used) && parsed.type == JSON_OBJ &&
        strcmp(json_get_str(json_get(&parsed, "schema")), schema) == 0) {
        *out = parsed;
        json_push_kv_int(out, "collector_status", rc);
        json_push_kv_bool(out, "collector_complete", rc == 0);
        json_push_kv_bool(out, "collector_deferred", rc != 0);
        if (rc != 0)
            json_push_kv_str(out, "collector_blocker",
                "collector returned typed output but did not complete successfully");
        return;
    }
    json_free(&parsed);
    json_set_object(out);
    json_push_kv_str(out, "schema", schema);
    json_push_kv_str(out, "status", "unavailable");
    json_push_kv_str(out, "collector_command", command);
    json_push_kv_int(out, "collector_status", rc);
    json_push_kv_bool(out, "collector_complete", false);
    json_push_kv_bool(out, "collector_deferred", true);
    json_push_kv_str(out, "collector_blocker",
                     "bounded collector failed or returned invalid typed output");
    json_push_kv_str(out, "agent_next_action",
                     "run the corresponding make target from the repository");
}
