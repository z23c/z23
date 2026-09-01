/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "controllers/node_binary_identity_json.h"

#include "json/json.h"
#include "net/version.h"
#include "util/clientversion.h"

void node_binary_identity_push_json(struct json_value *obj, const char *key,
                                    bool include_protocolversion)
{
    if (!obj)
        return;

    struct json_value sub = {0};
    struct json_value *target = obj;
    if (key) {
        json_init(&sub);
        json_set_object(&sub);
        target = &sub;
    }

    json_push_kv_int(target, "version", CLIENT_VERSION);
    json_push_kv_str(target, "subversion", CLIENT_NAME);
    if (key) {
        /* Preserve the pre-existing bootstrapstatus field name alongside
         * the new "subversion" field — same value, additive only. */
        json_push_kv_str(target, "client_name", CLIENT_NAME);
    }
    json_push_kv_str(target, "advertised_subver", msg_version_user_agent());
    if (include_protocolversion)
        json_push_kv_int(target, "protocolversion", PROTOCOL_VERSION);
    json_push_kv_str(target, "source_id_sha256",
                     zcl_build_source_id_sha256());
    json_push_kv_str(target, "build_commit", zcl_build_commit());

    if (key) {
        json_push_kv(obj, key, &sub);
        json_free(&sub);
    }
}
