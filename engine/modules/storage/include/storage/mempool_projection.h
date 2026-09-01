/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_STORAGE_MEMPOOL_PROJECTION_H
#define ZCL_STORAGE_MEMPOOL_PROJECTION_H

#include "storage/event_log.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct mempool_projection mempool_projection_t;

mempool_projection_t *mempool_projection_open(const char *projection_path,
                                              event_log_t *log);
void mempool_projection_close(mempool_projection_t *p);

uint64_t mempool_projection_catch_up(mempool_projection_t *p);

bool mempool_projection_get(mempool_projection_t *p,
                            const uint8_t txid[32],
                            int64_t *fee_out,
                            uint32_t *size_out,
                            uint32_t *weight_out);

typedef bool (*mempool_projection_cb)(const uint8_t txid[32],
                                      int64_t fee,
                                      uint32_t size_bytes,
                                      uint32_t weight,
                                      void *user);
int mempool_projection_each(mempool_projection_t *p,
                            mempool_projection_cb cb,
                            void *user);

uint64_t mempool_projection_count(mempool_projection_t *p);
int64_t mempool_projection_total_fee(mempool_projection_t *p);
uint64_t mempool_projection_total_weight(mempool_projection_t *p);

void mempool_projection_set_event_log(event_log_t *log);
event_log_t *mempool_projection_event_log(void);

bool mempool_projection_emit_admit(const uint8_t txid[32], int64_t fee,
                                   uint32_t size_bytes, uint32_t weight,
                                   int64_t admitted_unix,
                                   const uint8_t *raw_tx,
                                   size_t raw_tx_len);
bool mempool_projection_emit_remove(const uint8_t txid[32], uint8_t reason);

struct json_value;
bool mempool_projection_dump_state_json(struct json_value *out,
                                        const char *key);

#endif /* ZCL_STORAGE_MEMPOOL_PROJECTION_H */
