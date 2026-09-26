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

int main(void) {
    test_first_report();
    test_continuation_and_rejection();
    return 0;
}
