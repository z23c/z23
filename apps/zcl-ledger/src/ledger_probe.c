/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "ledger_hid.h"

int ledger_probe_parse(const uint8_t *reply, size_t reply_len) {
    static const uint8_t expected[] = {'Z', 'C', 'L', 1, 0, 0x90, 0x00};
    if (!reply || reply_len != sizeof expected) return -1;
    for (size_t i = 0; i < sizeof expected; ++i) {
        if (reply[i] != expected[i]) return -1;
    }
    return 0;
}
