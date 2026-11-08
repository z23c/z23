/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Read the producer receipt from a leased consensus bundle. */
#ifndef ZCL_CONSENSUS_STATE_INSTALL_SOURCE_RECEIPT_H
#define ZCL_CONSENSUS_STATE_INSTALL_SOURCE_RECEIPT_H
#include <stdbool.h>
struct sqlite3;
struct consensus_state_source_receipt;
bool icb_read_source_receipt(struct sqlite3 *bundle_db,
                             struct consensus_state_source_receipt *out);
#endif
