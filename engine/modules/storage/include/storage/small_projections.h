/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_STORAGE_SMALL_PROJECTIONS_H
#define ZCL_STORAGE_SMALL_PROJECTIONS_H

#include "storage/event_log.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct contacts_projection contacts_projection_t;
contacts_projection_t *contacts_projection_open(const char *path,
                                                event_log_t *log);
void contacts_projection_close(contacts_projection_t *p);
uint64_t contacts_projection_catch_up(contacts_projection_t *p);
/* Return the number of rows in the contacts table (0 when empty).
 * Returns UINT64_MAX on error — p or its db is NULL, the COUNT(*)
 * statement fails to prepare, or no row is returned. Callers must treat
 * UINT64_MAX as a failure sentinel, not a count. */
uint64_t contacts_projection_count(contacts_projection_t *p);
void contacts_projection_set_event_log(event_log_t *log);
bool contacts_projection_emit_set(const char *address, const char *name);
bool contacts_projection_emit_touched(const char *address,
                                      uint32_t last_used);
struct json_value;
bool contacts_projection_dump_state_json(struct json_value *out,
                                         const char *key);
contacts_projection_t *contacts_projection_current(void);

typedef struct onion_ann_projection onion_ann_projection_t;
onion_ann_projection_t *onion_ann_projection_open(const char *path,
                                                  event_log_t *log);
void onion_ann_projection_close(onion_ann_projection_t *p);
uint64_t onion_ann_projection_catch_up(onion_ann_projection_t *p);
uint64_t onion_ann_projection_count(onion_ann_projection_t *p);
void onion_ann_projection_set_event_log(event_log_t *log);
bool onion_ann_projection_emit(const char *onion_address,
                               uint32_t announced_at,
                               const char *script_hex);
bool onion_ann_projection_dump_state_json(struct json_value *out,
                                          const char *key);
onion_ann_projection_t *onion_ann_projection_current(void);

typedef struct hodl_history_projection hodl_history_projection_t;
hodl_history_projection_t *hodl_history_projection_open(
    const char *path, event_log_t *log);
void hodl_history_projection_close(hodl_history_projection_t *p);
uint64_t hodl_history_projection_catch_up(hodl_history_projection_t *p);
uint64_t hodl_history_projection_count(hodl_history_projection_t *p);
void hodl_history_projection_set_event_log(event_log_t *log);
bool hodl_history_projection_emit_snapshot(int32_t height,
                                           uint32_t time_unix,
                                           int64_t total_zat,
                                           int64_t older_1y_zat,
                                           double older_1y_pct);
bool hodl_history_projection_dump_state_json(struct json_value *out,
                                             const char *key);
hodl_history_projection_t *hodl_history_projection_current(void);

#endif /* ZCL_STORAGE_SMALL_PROJECTIONS_H */
