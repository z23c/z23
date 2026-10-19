/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: node-free build identity for `z23 version` (ops.debug.version). */

#include "command/native_command.h"

#include "config/boot.h"
#include "json/json.h"
#include "util/clientversion.h"

#include <stdio.h>

/* ops.debug.version — which build answered. Reads only compile-time identity
 * and the Tor link fact, so it works on a node that will not start. The
 * version string is the same major.minor.revision `z23 --version` prints, and
 * the tor value is the same "full" / "stub" word.
 * No git commit is reported: the executable does not embed one
 * (clientversion.h), so source_id is the identity. */
void zcl_native_handle_ops_debug_version(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    if (!reply)
        return;
    char version[32];
    (void)snprintf(version, sizeof(version), "%d.%d.%d",
                   CLIENT_VERSION_MAJOR, CLIENT_VERSION_MINOR,
                   CLIENT_VERSION_REVISION);
    (void)json_push_kv_str(&reply->data, "version", version);
    (void)json_push_kv_str(&reply->data, "source_id",
                           zcl_build_source_id_sha256());
    (void)json_push_kv_str(&reply->data, "tor",
                           app_tor_real_build_linked() ? "full" : "stub");
}
