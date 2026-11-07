/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Declare read-only local identity probing for copy personalization. */
#ifndef ZCL_NATIVE_APP_PERSONALIZE_COMMAND_H
#define ZCL_NATIVE_APP_PERSONALIZE_COMMAND_H
#include "command/native_command.h"
/* Probe only: no key creation, directory creation, signing or execution. */
bool app_personalize_key_probe(struct zcl_command_reply *reply,
    char *path, size_t path_cap, char pubkey_hex[67], bool *exists);
/* Derive the publisher component from one compressed public key; no I/O. */
bool app_personalize_namespace(const char *pubkey_hex, char *out, size_t out_cap);
void zcl_native_handle_app_personalize(const struct zcl_command_request *request,
                                       struct zcl_command_reply *reply);
#endif
