/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "ledger_hid.h"
#include "zcl_address.h"
#include "zcl_sign_test.h"

#include <fcntl.h>
#include <linux/hidraw.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int exchange(int fd, const uint8_t command[5], uint8_t *reply,
                    size_t capacity, size_t *payload_length) {
    size_t length = 0;
    if (ledger_hid_exchange(fd, command, 5, reply, capacity, &length) < 0 ||
        length < 2) return -1;
    uint16_t status = (uint16_t)(((uint16_t)reply[length - 2] << 8) |
                                  reply[length - 1]);
    if (status == 0x6985) return 1;
    if (status != 0x9000) return -1;
    *payload_length = length - 2;
    return 0;
}

static int sign_test(const char *path, bool json) {
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct hidraw_devinfo device;
    if (ioctl(fd, HIDIOCGRAWINFO, &device) < 0 ||
        device.vendor != 0x2c97 || device.product != 0x0000) {
        close(fd);
        return -1;
    }
    uint8_t reply[LEDGER_HID_MAX_RESPONSE];
    size_t length = 0;
    static const uint8_t identify[] = {0xa5, 0x01, 0, 0, 0};
    static const uint8_t expected[] = {'Z', 'C', 'L', 7, 0x02};
    if (exchange(fd, identify, reply, sizeof reply, &length) != 0 ||
        length != sizeof expected || memcmp(reply, expected, length) != 0) {
        close(fd);
        return -1;
    }
    static const uint8_t sign[] = {0xa5, 0x20, 0, 0, 0};
    int status = exchange(fd, sign, reply, sizeof reply, &length);
    close(fd);
    if (status != 0) return status;
    uint8_t pubkey[ZCL_SIGN_TEST_PUBKEY_SIZE];
    char address[ZCL_ADDRESS_SIZE];
    if (zcl_sign_test_verify(reply, length, pubkey) < 0 ||
        zcl_address_from_pubkey(pubkey, address) < 0) return -1;
    if (json) printf("{\"ok\":true,\"signature_verified\":true,"
                     "\"transaction_signed\":false,\"path\":\"%s\","
                     "\"address\":\"%s\",\"public_key\":\"",
                     ZCL_SIGN_TEST_PATH, address);
    else printf("Verified Blue signature for %s\nZCL address: %s\nPublic key: ",
                ZCL_SIGN_TEST_PATH, address);
    for (size_t i = 0; i < sizeof pubkey; ++i) printf("%02x", pubkey[i]);
    if (json) puts("\"}");
    else puts("\nFixed signing self-test only; no transaction was signed.");
    return 0;
}

int main(int argc, char **argv) {
    bool json = argc == 3 && strcmp(argv[1], "--json") == 0;
    if ((!json && argc != 2) || (json && argc != 3)) {
        fprintf(stderr, "Usage: %s [--json] /dev/hidrawN\n", argv[0]);
        return 2;
    }
    int result = sign_test(argv[json ? 2 : 1], json);
    if (result == 0) return 0;
    if (json) printf("{\"ok\":false,\"error\":\"%s\"}\n",
                     result == 1 ? "not_approved" : "sign_test_failed");
    else fputs(result == 1 ? "Tap SIGN TEST on the Blue, then retry.\n" :
               "Blue signing self-test failed; no transaction was signed.\n",
               stderr);
    return 1;
}
