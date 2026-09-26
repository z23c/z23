/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_review_protocol.h"
#include "ledger_hid.h"
#include "zcl_tx_review.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/hidraw.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

static int read_file(const char *path, uint8_t **bytes, size_t *length) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat info;
    if (fd < 0) return -1;
    if (fstat(fd, &info) < 0 || !S_ISREG(info.st_mode) ||
        info.st_size < 29 || info.st_size > ZCL_TX_REVIEW_MAX_BYTES) {
        close(fd);
        return -1;
    }
    size_t count = (size_t)info.st_size;
    uint8_t *buffer = malloc(count);
    if (!buffer) { close(fd); return -1; }
    size_t offset = 0;
    while (offset < count) {
        ssize_t got = read(fd, buffer + offset, count - offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        offset += (size_t)got;
    }
    uint8_t extra;
    ssize_t trailing = offset == count ? read(fd, &extra, 1) : -1;
    close(fd);
    if (offset != count || trailing != 0) { free(buffer); return -1; }
    *bytes = buffer;
    *length = count;
    return 0;
}

static int send_expected(int fd, const uint8_t *apdu, size_t apdu_length,
                         const uint8_t *expected, size_t expected_length) {
    uint8_t reply[LEDGER_HID_MAX_RESPONSE];
    size_t length = 0;
    if (ledger_hid_exchange_timeout(fd, apdu, apdu_length, reply,
                                    sizeof reply, &length, 5000) < 0 ||
        length != expected_length + 2 ||
        (expected_length && memcmp(reply, expected, expected_length) != 0) ||
        reply[length - 2] != 0x90 || reply[length - 1] != 0) return -1;
    return 0;
}

static int send_transaction(int fd, const uint8_t *wire, size_t length) {
    uint8_t command[5 + 220] = {0xa5, 0x10, 0, 0, 2};
    command[5] = (uint8_t)length;
    command[6] = (uint8_t)(length >> 8);
    if (send_expected(fd, command, 7, NULL, 0) < 0) return -1;
    for (size_t offset = 0; offset < length; offset += 220) {
        size_t count = length - offset < 220 ? length - offset : 220;
        command[1] = 0x11;
        command[4] = (uint8_t)count;
        memcpy(command + 5, wire + offset, count);
        if (send_expected(fd, command, 5 + count, NULL, 0) < 0) return -1;
    }
    return 0;
}

static int blue_review(const char *device, const uint8_t *wire, size_t length,
                       const zcl_tx_review *review) {
    if (length > ZCL_BLUE_REVIEW_MAX_BYTES) return -1;
    int fd = open(device, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    struct hidraw_devinfo info;
    if (fd < 0) return -1;
    if (ioctl(fd, HIDIOCGRAWINFO, &info) < 0 ||
        info.vendor != 0x2c97 || info.product != 0) {
        close(fd);
        return -1;
    }
    static const uint8_t probe[] = {0xa5, 1, 0, 0, 0};
    static const uint8_t identity[] = {'Z', 'C', 'L', 4, 0x40};
    uint8_t final[] = {0xa5, 0x12, 0, 0, 0};
    uint8_t summary[44];
    blue_review_encode_summary(review, summary);
    int result = send_expected(fd, probe, sizeof probe,
                               identity, sizeof identity) == 0 &&
                 send_transaction(fd, wire, length) == 0 &&
                 send_expected(fd, final, sizeof final,
                               summary, sizeof summary) == 0 ? 0 : -1;
    close(fd);
    return result;
}

static bool parse_args(int argc, char **argv, bool *json,
                       const char **device, const char **file) {
    int index = 1;
    *json = index < argc && strcmp(argv[index], "--json") == 0;
    if (*json) ++index;
    *device = NULL;
    if (index < argc && strcmp(argv[index], "--blue") == 0) {
        if (++index >= argc) return false;
        *device = argv[index++];
    }
    if (index != argc - 1) return false;
    *file = argv[index];
    return true;
}

int main(int argc, char **argv) {
    bool json;
    const char *device, *file;
    if (!parse_args(argc, argv, &json, &device, &file)) {
        fprintf(stderr, "Usage: %s [--json] [--blue /dev/hidrawN] TRANSACTION.bin\n",
                argv[0]);
        return 2;
    }
    uint8_t *wire = NULL;
    size_t length = 0;
    if (read_file(file, &wire, &length) < 0) {
        fputs("Cannot read a regular transaction file of 29 bytes to 2 MiB.\n", stderr);
        return 1;
    }
    zcl_tx_review review;
    int result = zcl_tx_review_parse(wire, length, &review);
    if (result == 0 && device) result = blue_review(device, wire, length, &review);
    free(wire);
    if (result < 0) {
        fputs("Transaction review failed; no signing was requested.\n", stderr);
        return 1;
    }
    if (json) {
        printf("{\"ok\":true,\"format\":\"zcl-sapling-v4\","
               "\"transparent_inputs\":%" PRIu32 ","
               "\"transparent_outputs\":%" PRIu32 ","
               "\"sapling_spends\":%" PRIu32 ","
               "\"sapling_outputs\":%" PRIu32 ","
               "\"sprout_joinsplits\":%" PRIu32 ","
               "\"transparent_output_zat\":%" PRIu64 ","
               "\"value_balance_zat\":%" PRId64 ","
               "\"lock_time\":%" PRIu32 ","
               "\"expiry_height\":%" PRIu32 ","
               "\"shielded_details_verified\":false,"
               "\"signing_ready\":false,"
               "\"blue_parsed\":%s}\n",
               review.transparent_inputs, review.transparent_outputs,
               review.sapling_spends, review.sapling_outputs,
               review.sprout_joinsplits, review.transparent_output_zat,
               review.value_balance_zat, review.lock_time,
               review.expiry_height, device ? "true" : "false");
    } else {
        printf("ZCL Sapling v4: %" PRIu32 " transparent input(s), %" PRIu32
               " output(s), %" PRIu32 " Sapling spend(s), %" PRIu32
               " Sapling output(s), %" PRIu32 " Sprout JoinSplit(s).\n",
               review.transparent_inputs, review.transparent_outputs,
               review.sapling_spends, review.sapling_outputs,
               review.sprout_joinsplits);
        printf("Public output total: %" PRIu64 " zatoshi; value balance: %" PRId64
               " zatoshi.\n", review.transparent_output_zat,
               review.value_balance_zat);
        puts("Structural review only. Shielded recipients, amounts, fee, proofs, and signatures are unverified.");
        if (device) puts("The Blue returned the same structural summary; no key operation occurred.");
    }
    return 0;
}
