/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "ledger_hid.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

static uint16_t read_be16(const uint8_t *bytes) {
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

int ledger_hid_encode(const uint8_t *payload, size_t payload_len,
                      uint16_t sequence, uint8_t report[LEDGER_HID_REPORT_SIZE],
                      size_t *consumed) {
    if (!payload || !report || !consumed || payload_len > UINT16_MAX ||
        (!sequence && !payload_len)) return -1;
    memset(report, 0, LEDGER_HID_REPORT_SIZE);
    report[0] = 1;
    report[1] = 1;
    report[2] = 5;
    report[3] = (uint8_t)(sequence >> 8);
    report[4] = (uint8_t)sequence;
    size_t header = sequence ? 5u : 7u;
    if (!sequence) {
        report[5] = (uint8_t)(payload_len >> 8);
        report[6] = (uint8_t)payload_len;
    }
    size_t n = payload_len < LEDGER_HID_REPORT_SIZE - header
                   ? payload_len : LEDGER_HID_REPORT_SIZE - header;
    memcpy(report + header, payload, n);
    *consumed = n;
    return 0;
}

int ledger_hid_decode(const uint8_t report[LEDGER_HID_REPORT_SIZE],
                      uint16_t sequence, size_t *declared_len,
                      const uint8_t **chunk, size_t *chunk_len) {
    if (!report || !declared_len || !chunk || !chunk_len ||
        report[0] != 1 || report[1] != 1 || report[2] != 5 ||
        read_be16(report + 3) != sequence) return -1;
    size_t header = sequence ? 5u : 7u;
    if (!sequence) *declared_len = read_be16(report + 5);
    *chunk = report + header;
    *chunk_len = LEDGER_HID_REPORT_SIZE - header;
    return 0;
}

static int transfer(int fd, short events, uint8_t *buffer, size_t len,
                    int timeout_ms) {
    struct pollfd pfd = {.fd = fd, .events = events};
    int ready;
    do ready = poll(&pfd, 1, timeout_ms); while (ready < 0 && errno == EINTR);
    if (ready <= 0 || !(pfd.revents & events)) return -1;
    ssize_t count;
    do {
        count = events == POLLOUT ? write(fd, buffer, len) : read(fd, buffer, len);
    } while (count < 0 && errno == EINTR);
    return count == (ssize_t)len ? 0 : -1;
}

int ledger_hid_exchange_timeout(int fd, const uint8_t *apdu, size_t apdu_len,
                                uint8_t *response, size_t response_cap,
                                size_t *response_len, int timeout_ms) {
    if (fd < 0 || !apdu || !apdu_len || apdu_len > UINT16_MAX ||
        !response || !response_len || response_cap < 2 || timeout_ms < 1) return -1;
    uint8_t report[LEDGER_HID_REPORT_SIZE + 1] = {0};
    uint16_t sequence = 0;
    size_t offset = 0;
    while (offset < apdu_len) {
        size_t consumed;
        if (ledger_hid_encode(apdu + offset, apdu_len - offset, sequence,
                              report + 1, &consumed) < 0 ||
            transfer(fd, POLLOUT, report, sizeof report, timeout_ms) < 0) return -1;
        offset += consumed;
        if (sequence == UINT16_MAX) return -1;
        ++sequence;
    }
    sequence = 0;
    offset = 0;
    size_t declared = 0;
    do {
        if (transfer(fd, POLLIN, report, LEDGER_HID_REPORT_SIZE,
                     timeout_ms) < 0) return -1;
        const uint8_t *chunk;
        size_t available;
        if (ledger_hid_decode(report, sequence, &declared, &chunk,
                              &available) < 0 || declared < 2 ||
            declared > response_cap || declared > LEDGER_HID_MAX_RESPONSE ||
            offset > declared) return -1;
        size_t remaining = declared - offset;
        size_t n = remaining < available ? remaining : available;
        memcpy(response + offset, chunk, n);
        offset += n;
        if (sequence == UINT16_MAX) return -1;
        ++sequence;
    } while (offset < declared);
    *response_len = declared;
    return 0;
}

int ledger_hid_exchange(int fd, const uint8_t *apdu, size_t apdu_len,
                        uint8_t *response, size_t response_cap,
                        size_t *response_len) {
    return ledger_hid_exchange_timeout(fd, apdu, apdu_len, response,
                                       response_cap, response_len, 3000);
}
