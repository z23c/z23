/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */
#ifndef ZCLASSIC23_CONTROLLERS_NODE_BINARY_IDENTITY_JSON_H
#define ZCLASSIC23_CONTROLLERS_NODE_BINARY_IDENTITY_JSON_H

/* Single serializer for the version/build identity fields shared by
 * rpc_getinfo (version/protocolversion), rpc_getnetworkinfo
 * (version/subversion/advertised_subver/protocolversion), and
 * rpc_bootstrapstatus (a nested "binary" object with
 * version/client_name/advertised_subver/source_id_sha256/build_commit). */

#include <stdbool.h>

struct json_value;

/* Pushes version/subversion/advertised_subver/[protocolversion], the
 * authoritative source_id_sha256, and display-only build_commit metadata.
 *
 * key == NULL: fields are pushed directly into obj (the getinfo /
 * getnetworkinfo shape — flat, top level).
 *
 * key != NULL: fields are pushed into a nested sub-object stored at
 * obj[key] (the bootstrapstatus "binary" shape). The nested form also
 * pushes "client_name" alongside "subversion" (same CLIENT_NAME value) to
 * preserve the field name bootstrapstatus already emits.
 *
 * include_protocolversion controls whether "protocolversion" is included —
 * bootstrapstatus already reports protocolversion in its separate "p2p"
 * sub-object, so its caller passes false to avoid a redundant field. */
void node_binary_identity_push_json(struct json_value *obj, const char *key,
                                    bool include_protocolversion);

#endif /* ZCLASSIC23_CONTROLLERS_NODE_BINARY_IDENTITY_JSON_H */
