/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Local reproduction-evidence gate for package POINTER publishes. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_DHT_PUBLISH_GATE_H
#define ZCL_CONFIG_BOOT_ZCODE_DHT_PUBLISH_GATE_H

#include "vcs/zcode_dht_service.h"

#include <stdbool.h>

struct json_value;

/* A zclassic23.package POINTER record claims "this exact package_root is
 * discoverable and fetchable from me". That claim is only honest when this
 * node's own store holds a committed release naming the root AND the store's
 * receipts directory evidences reproduction: >= 2 distinct byte-identical
 * installable build receipts for the exact (package_root, recipe_root) pair
 * the signed release commits (vcs_package_reproduce_scan). Everything else
 * refuses BEFORE a plan token exists, so plan and commit are gated
 * identically. Returns true when the publish may proceed; on refusal result
 * carries the exact named code (NO_PACKAGE_STORE, PACKAGE_INDEX_UNAVAILABLE,
 * UNKNOWN_PACKAGE, RELEASE_UNREADABLE, REPRODUCTION_NOT_EVIDENCED) in the
 * ok/code/message shape every RPC refusal in this layer uses. */
bool boot_zcode_dht_package_pointer_publish_gate(
    const struct vcs_zcode_dht_publish_spec *spec, struct json_value *result);

#endif /* ZCL_CONFIG_BOOT_ZCODE_DHT_PUBLISH_GATE_H */
