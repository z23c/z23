/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */
#ifndef ZCLASSIC23_CONTROLLERS_BLOCK_INTAKE_JSON_H
#define ZCLASSIC23_CONTROLLERS_BLOCK_INTAKE_JSON_H

#include <stdbool.h>

struct json_value;

void controller_json_set_block_intake_stats(struct json_value *obj);
void controller_json_push_block_intake_stats(struct json_value *obj);
bool controller_block_intake_dump_state_json(struct json_value *out,
                                             const char *key);

#endif /* ZCLASSIC23_CONTROLLERS_BLOCK_INTAKE_JSON_H */
