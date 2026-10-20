/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: input and reply helpers the plugin command handlers share. */
#ifndef ZCL_NATIVE_PLUGIN_COMMON_H
#define ZCL_NATIVE_PLUGIN_COMMON_H

#include "command/native_command.h"

#include <stdbool.h>

struct json_value;

/* The string input named key, or NULL when absent or not a string. */
const char *plg_str(const struct zcl_command_request *request, const char *key);
/* Pushes "capabilities" (an array of vocabulary names) onto obj. */
void plg_push_capabilities(struct json_value *obj, unsigned mask);
/* Reads "cap" (comma list or JSON array) into mask; false when invalid. */
bool plg_capabilities(const struct zcl_command_request *request, unsigned *mask);

#endif
