/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model: FileService
 *
 * Tracks peer file service endpoints for block file downloads.
 *
 * validates :ip, presence: true
 * validates :port, not_zero: true
 * validates :is_zcl23, inclusion: [0, 1]
 */

#ifndef ZCL_DB_MODEL_FILE_SERVICE_H
#define ZCL_DB_MODEL_FILE_SERVICE_H

#include "models/database.h"
#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

struct db_file_service {
    uint8_t  ip[16];
    uint16_t port;
    uint16_t p2p_port;
    int64_t  last_seen;
    bool     is_zcl23;
};

/* Callbacks and validation */
struct ar_callbacks *db_file_service_callbacks(void);
bool db_file_service_validate(const struct db_file_service *fs,
                              struct ar_errors *errors);

bool db_file_service_save(struct node_db *ndb,
                          const struct db_file_service *fs);




/* Get recently-seen file services for download scheduling. */
int db_file_service_recent(struct node_db *ndb,
                           struct db_file_service *out, size_t max);

#endif
