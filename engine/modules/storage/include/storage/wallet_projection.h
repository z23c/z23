/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_STORAGE_WALLET_PROJECTION_H
#define ZCL_STORAGE_WALLET_PROJECTION_H

#include "storage/event_log.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct wallet_projection wallet_projection_t;

wallet_projection_t *wallet_projection_open(const char *projection_path,
                                            event_log_t *log);
void wallet_projection_close(wallet_projection_t *p);

uint64_t wallet_projection_catch_up(wallet_projection_t *p);

uint64_t wallet_projection_address_count(wallet_projection_t *p);
uint64_t wallet_projection_tx_count(wallet_projection_t *p);
uint64_t wallet_projection_utxo_count(wallet_projection_t *p);
uint64_t wallet_projection_note_count(wallet_projection_t *p);
int64_t wallet_projection_total_value_zat(wallet_projection_t *p);

void wallet_projection_set_event_log(event_log_t *log);
event_log_t *wallet_projection_event_log(void);
wallet_projection_t *wallet_projection_current(void);

bool wallet_projection_emit_key_add(const uint8_t pubkey_hash[20],
                                    const char *address,
                                    const char *label,
                                    uint32_t created_unix);
bool wallet_projection_emit_addr_derived(
    const uint8_t pubkey_hash[20],
    const uint8_t derived_pubkey_hash[20],
    uint32_t derivation_index,
    uint32_t derived_unix);
bool wallet_projection_emit_tx_seen(const uint8_t txid[32],
                                    int32_t block_height,
                                    int64_t fee,
                                    uint8_t from_me);
bool wallet_projection_emit_utxo_seen(const uint8_t txid[32],
                                      uint32_t vout,
                                      int64_t value,
                                      const uint8_t address_hash[20],
                                      int32_t height,
                                      uint8_t is_coinbase);
bool wallet_projection_emit_note_decrypted(const uint8_t txid[32],
                                           uint32_t output_index,
                                           int64_t value,
                                           const uint8_t cm[32],
                                           int32_t block_height);

struct json_value;
bool wallet_projection_dump_state_json(struct json_value *out,
                                       const char *key);

#endif /* ZCL_STORAGE_WALLET_PROJECTION_H */
