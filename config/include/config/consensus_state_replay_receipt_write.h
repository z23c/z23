/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Atomically publish independently derived consensus replay receipts. */
#ifndef ZCL_CONSENSUS_STATE_REPLAY_RECEIPT_WRITE_H
#define ZCL_CONSENSUS_STATE_REPLAY_RECEIPT_WRITE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool consensus_state_replay_receipt_write(const char *datadir,
                                          const uint8_t *payload,
                                          size_t payload_size,
                                          char *final_out,
                                          size_t final_cap);

#endif
