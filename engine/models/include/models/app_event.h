/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Immutable, signature-verified AppEvent persistence shared by Blog, Social,
 * Chat, games, and future manifest-declared App topics.  Payload storage is
 * caller-owned on reads so a metadata scan never allocates or copies 64 KiB
 * per row. */

#ifndef ZCL_DB_MODEL_APP_EVENT_H
#define ZCL_DB_MODEL_APP_EVENT_H

#include "framework/app_platform.h"
#include "models/activerecord.h"
#include "models/database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct db_app_event {
    struct zcl_app_signed_event_v1 event;
    int64_t receive_cursor;
    int64_t received_at;
};

/* Payload-free row used by inventory, pagination, and relationship scans. */
struct db_app_event_ref {
    int64_t receive_cursor;
    uint8_t event_id[32];
    char app_id[ZCL_APP_ID_MAX + 1];
    char topic[ZCL_APP_TOPIC_MAX + 1];
    uint32_t kind;
    uint8_t author_key_id[ZCL_APP_EVENT_KEY_ID_SIZE];
    uint64_t sequence;
    uint8_t previous_event_id[32];
    int64_t created_at;
    int64_t received_at;
};

struct ar_callbacks *db_app_event_callbacks(void);

/* ActiveRecord shape validation only. Persistence and reads additionally
 * require a host-owned scope so an event cannot authorize its own App, topic,
 * chain, or byte budget. */
bool db_app_event_validate(const struct db_app_event *record,
                           struct ar_errors *errors);

/* Save is immutable and idempotent by event_id. The signed event's payload is
 * borrowed only for the duration of this call. `scope` is trusted host policy,
 * normally compiled from the App catalog; it is never derived from `record`.
 * A cryptographically valid event whose event_id is already bound to different
 * bytes fails closed. */
bool db_app_event_save(struct node_db *ndb,
                       const struct db_app_event *record,
                       const struct zcl_app_event_scope_v1 *scope);

/* `payload` becomes out->event.payload.data and must remain alive while `out`
 * is used. A short buffer or scope mismatch fails without returning a partial
 * event. */
bool db_app_event_find(struct node_db *ndb, const uint8_t event_id[32],
                       const struct zcl_app_event_scope_v1 *scope,
                       struct db_app_event *out,
                       uint8_t *payload, size_t payload_capacity);

int db_app_event_count(struct node_db *ndb, const char *app_id,
                       const char *topic_or_null);

/* Keyset inventory: rows strictly after `after_cursor`, ordered by the local
 * receive cursor. Arrival order is never used to choose an App projection. */
int db_app_event_topic_after(struct node_db *ndb,
                             const char *app_id, const char *topic,
                             int64_t after_cursor,
                             struct db_app_event_ref *out, size_t max);

/* AppEvent belongs_to :previous_event. Missing predecessors are normal during
 * anti-entropy and return false; an identity/sequence mismatch fails closed. */
bool db_app_event_previous(struct node_db *ndb,
                           const struct db_app_event *record,
                           const struct zcl_app_event_scope_v1 *scope,
                           struct db_app_event *out,
                           uint8_t *payload, size_t payload_capacity);

/* AppEvent has_many :successors. Every valid fork is retained and returned in
 * deterministic sequence/event-id order, independent of arrival order. */
int db_app_event_successors(struct node_db *ndb,
                            const struct db_app_event *record,
                            const struct zcl_app_event_scope_v1 *scope,
                            struct db_app_event_ref *out, size_t max);

#endif /* ZCL_DB_MODEL_APP_EVENT_H */
