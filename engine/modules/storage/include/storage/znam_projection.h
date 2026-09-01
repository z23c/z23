/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_STORAGE_ZNAM_PROJECTION_H
#define ZCL_STORAGE_ZNAM_PROJECTION_H

#include "storage/event_log.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct znam_projection znam_projection_t;

znam_projection_t *znam_projection_open(const char *projection_path,
                                        event_log_t *log);
void znam_projection_close(znam_projection_t *p);

uint64_t znam_projection_catch_up(znam_projection_t *p);

/* Read accessors — Read-only; safe under concurrent readers. */

/* Look up a registered name. On a hit, fills the caller-supplied output
 * parameters (each optional — pass NULL / cap 0 to skip):
 *   owner_out (owner_cap, recommend >=65): owner address, NUL-terminated.
 *   target_type_out: primary target's coin/record type byte.
 *   target_value_out (target_cap, recommend >=129): primary target
 *     value, NUL-terminated.
 *   reg_height_out: block height the name was registered at.
 *   expiry_height_out: block height the registration expires at.
 * Text outputs are always NUL-terminated (truncated to fit the cap).
 * Returns true if `name` is found, false otherwise — including when
 * `p`, its db, or `name` is NULL, or the query fails. On false no
 * output parameter is written. */
bool znam_projection_find(znam_projection_t *p, const char *name,
                          char *owner_out, size_t owner_cap,
                          uint8_t *target_type_out,
                          char *target_value_out, size_t target_cap,
                          int32_t *reg_height_out,
                          int32_t *expiry_height_out);

bool znam_projection_addr_get(znam_projection_t *p, const char *name,
                              uint8_t coin_type,
                              char *addr_out, size_t addr_cap);

bool znam_projection_text_get(znam_projection_t *p, const char *name,
                              const char *key,
                              char *value_out, size_t value_cap);

uint64_t znam_projection_name_count(znam_projection_t *p);
uint64_t znam_projection_addr_count(znam_projection_t *p);
uint64_t znam_projection_text_count(znam_projection_t *p);

/* Process-global projection wiring used by the ZNAM model. NULL log
 * disables emission and keeps legacy writes authoritative. Mirrors the
 * peers_projection pattern.
 */
void znam_projection_set_event_log(event_log_t *log);
event_log_t *znam_projection_event_log(void);

bool znam_projection_emit_register(const char *name, const char *owner,
                                   uint8_t target_type,
                                   const char *target_value,
                                   const uint8_t reg_txid[32],
                                   int32_t reg_height,
                                   uint32_t registered_unix,
                                   int32_t expiry_height);

bool znam_projection_emit_update_addr(const char *name, uint8_t coin_type,
                                      const char *address,
                                      const uint8_t update_txid[32]);

bool znam_projection_emit_update_text(const char *name, const char *key,
                                      const char *value,
                                      const uint8_t update_txid[32]);

struct json_value;
bool znam_projection_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_STORAGE_ZNAM_PROJECTION_H */
