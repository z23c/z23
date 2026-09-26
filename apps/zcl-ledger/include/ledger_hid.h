/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_LEDGER_HID_H
#define ZCL_LEDGER_HID_H

#include <stddef.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The ZCL Ledger host requires ISO C23"
#endif

enum { LEDGER_HID_REPORT_SIZE = 64, LEDGER_HID_MAX_RESPONSE = 4096 };

/* The payload includes the two-byte application status word. */
int ledger_hid_exchange(int fd, const uint8_t *apdu, size_t apdu_len,
                        uint8_t *response, size_t response_cap,
                        size_t *response_len);

/* Pure packet codec. A negative result rejects a malformed packet. */
int ledger_hid_encode(const uint8_t *payload, size_t payload_len,
                      uint16_t sequence, uint8_t report[LEDGER_HID_REPORT_SIZE],
                      size_t *consumed);
int ledger_hid_decode(const uint8_t report[LEDGER_HID_REPORT_SIZE],
                      uint16_t sequence, size_t *declared_len,
                      const uint8_t **chunk, size_t *chunk_len);

#endif
