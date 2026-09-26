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

int ledger_fixture_probe_parse(const uint8_t *reply, size_t reply_len) {
    static const uint8_t expected[] = {'Z', 'C', 'L', 3, 0x80, 0x90, 0x00};
    if (!reply || reply_len != sizeof expected) return -1;
    for (size_t i = 0; i < sizeof expected; ++i) {
        if (reply[i] != expected[i]) return -1;
    }
    return 0;
}

int ledger_fixture_key_parse(const uint8_t *reply, size_t reply_len) {
    static const uint8_t expected[] = {
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
        0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
        0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        0x90, 0x00
    };
    if (!reply || reply_len != sizeof expected) return -1;
    for (size_t i = 0; i < sizeof expected; ++i) {
        if (reply[i] != expected[i]) return -1;
    }
    return 0;
}
