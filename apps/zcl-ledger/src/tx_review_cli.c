/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "zcl_tx_review.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) {
        fprintf(stderr, "Usage: %s [--json] TRANSACTION.bin\n", argv[0]);
        return 2;
    }
    bool json = argc == 3;
    if (json && strcmp(argv[1], "--json") != 0) {
        fprintf(stderr, "Usage: %s [--json] TRANSACTION.bin\n", argv[0]);
        return 2;
    }
    uint8_t *wire = NULL;
    size_t length = 0;
    if (read_file(argv[argc - 1], &wire, &length) < 0) {
        fputs("Cannot read a regular transaction file of 29 bytes to 2 MiB.\n", stderr);
        return 1;
    }
    zcl_tx_review review;
    int result = zcl_tx_review_parse(wire, length, &review);
    free(wire);
    if (result < 0) {
        fputs("Invalid or unsupported ZCL Sapling-v4 transaction.\n", stderr);
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
               "\"signing_ready\":false}\n",
               review.transparent_inputs, review.transparent_outputs,
               review.sapling_spends, review.sapling_outputs,
               review.sprout_joinsplits, review.transparent_output_zat,
               review.value_balance_zat, review.lock_time,
               review.expiry_height);
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
    }
    return 0;
}
