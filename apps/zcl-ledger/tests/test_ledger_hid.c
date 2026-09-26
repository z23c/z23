/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "ledger_hid.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

static void test_first_report(void) {
    const uint8_t apdu[] = {0xb0, 1, 0, 0, 0};
    uint8_t report[LEDGER_HID_REPORT_SIZE];
    size_t consumed;
    assert(ledger_hid_encode(apdu, sizeof apdu, 0, report, &consumed) == 0);
    assert(consumed == sizeof apdu);
    const uint8_t expected[] = {1, 1, 5, 0, 0, 0, 5, 0xb0, 1, 0, 0, 0};
    assert(memcmp(report, expected, sizeof expected) == 0);
    size_t declared = 0;
    size_t chunk_len = 0;
    const uint8_t *chunk = NULL;
    assert(ledger_hid_decode(report, 0, &declared, &chunk, &chunk_len) == 0);
    assert(declared == sizeof apdu && chunk_len == 57);
    assert(memcmp(chunk, apdu, sizeof apdu) == 0);
}

static void test_continuation_and_rejection(void) {
    uint8_t payload[80];
    for (size_t i = 0; i < sizeof payload; ++i) payload[i] = (uint8_t)i;
    uint8_t report[LEDGER_HID_REPORT_SIZE];
    size_t consumed;
    assert(ledger_hid_encode(payload, sizeof payload, 0, report, &consumed) == 0);
    assert(consumed == 57);
    assert(ledger_hid_encode(payload + consumed, sizeof payload - consumed,
                             1, report, &consumed) == 0);
    assert(consumed == 23);
    const uint8_t *chunk;
    size_t chunk_len;
    size_t declared = 80;
    assert(ledger_hid_decode(report, 1, &declared, &chunk, &chunk_len) == 0);
    assert(chunk_len == 59 && memcmp(chunk, payload + 57, 23) == 0);
    assert(ledger_hid_decode(report, 2, &declared, &chunk, &chunk_len) < 0);
    report[2] = 4;
    assert(ledger_hid_decode(report, 1, &declared, &chunk, &chunk_len) < 0);
}

static void test_probe_rejects_other_apps_and_permissions(void) {
    uint8_t reply[] = {'Z', 'C', 'L', 1, 0, 0x90, 0x00};
    assert(ledger_probe_parse(reply, sizeof reply) == 0);
    assert(ledger_probe_parse(NULL, sizeof reply) < 0);
    assert(ledger_probe_parse(reply, sizeof reply - 1) < 0);
    reply[3] = 2;
    assert(ledger_probe_parse(reply, sizeof reply) < 0);
    reply[3] = 1;
    reply[4] = 1;
    assert(ledger_probe_parse(reply, sizeof reply) < 0);
    reply[4] = 0;
    reply[0] = 'B';
    assert(ledger_probe_parse(reply, sizeof reply) < 0);
    reply[0] = 'Z';
    reply[5] = 0x6d;
    assert(ledger_probe_parse(reply, sizeof reply) < 0);
}

static void test_public_fixture_protocol(void) {
    uint8_t probe[] = {'Z', 'C', 'L', 3, 0x80, 0x90, 0x00};
    assert(ledger_fixture_probe_parse(probe, sizeof probe) == 0);
    probe[4] = 1;
    assert(ledger_fixture_probe_parse(probe, sizeof probe) < 0);
    probe[4] = 0x80;
    assert(ledger_fixture_probe_parse(probe, sizeof probe - 1) < 0);
    uint8_t key[] = {
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
        0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
        0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        0x90, 0x00
    };
    assert(ledger_fixture_key_parse(key, sizeof key) == 0);
    key[0] = 3;
    assert(ledger_fixture_key_parse(key, sizeof key) < 0);
    key[0] = 2;
    key[34] = 1;
    assert(ledger_fixture_key_parse(key, sizeof key) < 0);
}

int main(void) {
    test_first_report();
    test_continuation_and_rejection();
    test_probe_rejects_other_apps_and_permissions();
    test_public_fixture_protocol();
    return 0;
}
