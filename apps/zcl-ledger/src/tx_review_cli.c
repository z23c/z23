/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_review_protocol.h"
#include "ledger_hid.h"
#include "zcl_tx_review.h"
#include "zcl_tx_script_facts.h"
#include "zcl_zip243_host.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/hidraw.h>
#include <openssl/sha.h>
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
                       const zcl_tx_review *review, bool has_branch,
                       uint32_t branch_id, const uint8_t zip_digest[32]) {
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
    static const uint8_t identity[] = {'Z', 'C', 'L', 6, 0x40};
    uint8_t final[] = {0xa5, 0x12, 0, 0, 0};
    uint8_t zip_command[9] = {0xa5, 0x14, 0, 0, 4};
    for (unsigned i = 0; i < 4; ++i)
        zip_command[5 + i] = (uint8_t)(branch_id >> (8 * i));
    uint8_t summary[76];
    blue_review_encode_summary(review, summary);
    if (!SHA256(wire, length, summary + 44)) {
        close(fd);
        return -1;
    }
    int result = send_expected(fd, probe, sizeof probe,
                               identity, sizeof identity) == 0 &&
                 send_transaction(fd, wire, length) == 0 &&
                 (!has_branch ||
                  send_expected(fd, zip_command, sizeof zip_command,
                                zip_digest, 32) == 0) &&
                 send_expected(fd, final, sizeof final,
                               summary, sizeof summary) == 0 ? 0 : -1;
    close(fd);
    return result;
}

static bool parse_branch(const char *text, uint32_t *branch) {
    if (strlen(text) != 10 || text[0] != '0' || text[1] != 'x') return false;
    uint32_t value = 0;
    for (size_t i = 2; i < 10; ++i) {
        char digit = text[i];
        unsigned nibble;
        if (digit >= '0' && digit <= '9') nibble = (unsigned)(digit - '0');
        else if (digit >= 'a' && digit <= 'f') nibble = (unsigned)(digit - 'a' + 10);
        else if (digit >= 'A' && digit <= 'F') nibble = (unsigned)(digit - 'A' + 10);
        else return false;
        value = (value << 4) | nibble;
    }
    *branch = value;
    return true;
}

static bool parse_args(int argc, char **argv, bool *json,
                       const char **device, bool *has_branch,
                       uint32_t *branch, const char **file) {
    int index = 1;
    *json = index < argc && strcmp(argv[index], "--json") == 0;
    if (*json) ++index;
    *device = NULL;
    if (index < argc && strcmp(argv[index], "--blue") == 0) {
        if (++index >= argc) return false;
        *device = argv[index++];
    }
    *has_branch = index < argc && strcmp(argv[index], "--branch-id") == 0;
    if (*has_branch) {
        if (++index >= argc || !parse_branch(argv[index++], branch)) return false;
    }
    if (index != argc - 1) return false;
    *file = argv[index];
    return true;
}

static int zip243_digest(const uint8_t *wire, size_t length,
                         uint32_t branch_id, uint8_t digest[32]) {
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    return zcl_zip243_shielded_digest(wire, length, branch_id,
                                      &hasher, digest);
}

static void print_hex(const uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; ++i) printf("%02x", bytes[i]);
}

static void print_review_json(const zcl_tx_review *review,
                              const zcl_tx_script_facts *scripts,
                              const char *device, bool has_branch,
                              uint32_t branch_id, const uint8_t zip_digest[32]) {
    printf("{\"ok\":true,\"format\":\"zcl-sapling-v4\","
           "\"transparent_inputs\":%" PRIu32 ","
           "\"transparent_outputs\":%" PRIu32 ","
           "\"sapling_spends\":%" PRIu32 ","
           "\"sapling_outputs\":%" PRIu32 ","
           "\"sprout_joinsplits\":%" PRIu32 ","
           "\"p2sh_outputs\":%" PRIu32 ","
           "\"op_return_outputs\":%" PRIu32 ","
           "\"zslp_marker\":%s,"
           "\"transparent_output_zat\":%" PRIu64 ","
           "\"value_balance_zat\":%" PRId64 ","
           "\"lock_time\":%" PRIu32 ","
           "\"expiry_height\":%" PRIu32 ","
           "\"shielded_details_verified\":false,"
           "\"signing_ready\":false,"
           "\"blue_parsed\":%s",
           review->transparent_inputs, review->transparent_outputs,
           review->sapling_spends, review->sapling_outputs,
           review->sprout_joinsplits, scripts->p2sh_outputs,
           scripts->op_return_outputs,
           scripts->zslp_marker ? "true" : "false",
           review->transparent_output_zat,
           review->value_balance_zat, review->lock_time,
           review->expiry_height, device ? "true" : "false");
    if (has_branch) {
        printf(",\"zip243_branch_id\":\"0x%08" PRIx32 "\",\"zip243_shielded_digest\":\"",
               branch_id);
        print_hex(zip_digest, 32);
        printf("\",\"blue_zip243_matched\":%s", device ? "true" : "false");
    }
    puts("}");
}

static void print_review_text(const zcl_tx_review *review,
                              const zcl_tx_script_facts *scripts,
                              const char *device, bool has_branch,
                              uint32_t branch_id, const uint8_t zip_digest[32]) {
    printf("ZCL Sapling v4: %" PRIu32 " transparent input(s), %" PRIu32
           " output(s), %" PRIu32 " Sapling spend(s), %" PRIu32
           " Sapling output(s), %" PRIu32 " Sprout JoinSplit(s).\n",
           review->transparent_inputs, review->transparent_outputs,
           review->sapling_spends, review->sapling_outputs,
           review->sprout_joinsplits);
    printf("Script outputs: %" PRIu32 " P2SH, %" PRIu32
           " OP_RETURN; first output has ZSLP marker: %s.\n",
           scripts->p2sh_outputs, scripts->op_return_outputs,
           scripts->zslp_marker ? "yes" : "no");
    printf("Public output total: %" PRIu64 " zatoshi; value balance: %" PRId64
           " zatoshi.\n", review->transparent_output_zat,
           review->value_balance_zat);
    puts("Structural review only. Shielded recipients, amounts, fee, proofs, and signatures are unverified.");
    if (device) puts("The Blue returned the same structural summary; no key operation occurred.");
    if (has_branch) {
        printf("ZIP-243 shielded digest for branch 0x%08" PRIx32 ": ", branch_id);
        print_hex(zip_digest, 32);
        putchar('\n');
        if (device) puts("Blue and host ZIP-243 digests matched; no signing was requested.");
    }
}

int main(int argc, char **argv) {
    bool json;
    const char *device, *file;
    bool has_branch;
    uint32_t branch_id = 0;
    if (!parse_args(argc, argv, &json, &device, &has_branch,
                    &branch_id, &file)) {
        fprintf(stderr, "Usage: %s [--json] [--blue /dev/hidrawN] [--branch-id 0xXXXXXXXX] TRANSACTION.bin\n",
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
    zcl_tx_script_facts scripts;
    uint8_t zip_digest[32] = {0};
    int result = zcl_tx_review_parse(wire, length, &review);
    if (result == 0)
        result = zcl_tx_script_facts_parse(wire, length, &scripts);
    if (result == 0 && has_branch)
        result = zip243_digest(wire, length, branch_id, zip_digest);
    if (result == 0 && device)
        result = blue_review(device, wire, length, &review,
                             has_branch, branch_id, zip_digest);
    free(wire);
    if (result < 0) {
        fputs("Transaction review failed; no signing was requested.\n", stderr);
        return 1;
    }
    if (json)
        print_review_json(&review, &scripts, device, has_branch,
                          branch_id, zip_digest);
    else
        print_review_text(&review, &scripts, device, has_branch,
                          branch_id, zip_digest);
    return 0;
}
