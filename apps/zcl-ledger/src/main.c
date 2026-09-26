/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "ledger_hid.h"

#include <fcntl.h>
#include <linux/hidraw.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int valid_field(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (data[i] < 0x20 || data[i] > 0x7e) return -1;
    }
    return 0;
}

static int show_app_info(int fd) {
    static const uint8_t command[] = {0xb0, 0x01, 0, 0, 0};
    uint8_t reply[LEDGER_HID_MAX_RESPONSE];
    size_t size;
    if (ledger_hid_exchange(fd, command, sizeof command, reply,
                            sizeof reply, &size) < 0) {
        fputs("Ledger did not answer the read-only app-info command.\n", stderr);
        return 1;
    }
    uint16_t status = (uint16_t)(((uint16_t)reply[size - 2] << 8) | reply[size - 1]);
    if (status != 0x9000) {
        fprintf(stderr, "Ledger returned status %04x.\n", status);
        return 1;
    }
    size_t end = size - 2;
    if (end < 5 || reply[0] != 1) {
        fputs("Unexpected app-info format.\n", stderr);
        return 1;
    }
    size_t pos = 1;
    size_t name_len = reply[pos++];
    if (name_len > end - pos) goto invalid;
    const uint8_t *name = reply + pos;
    pos += name_len;
    if (pos >= end) goto invalid;
    size_t version_len = reply[pos++];
    if (version_len > end - pos) goto invalid;
    const uint8_t *version = reply + pos;
    pos += version_len;
    if (pos >= end) goto invalid;
    size_t flags_len = reply[pos++];
    if (flags_len != end - pos || valid_field(name, name_len) < 0 ||
        valid_field(version, version_len) < 0) goto invalid;
    printf("%.*s %.*s\n", (int)name_len, (const char *)name,
           (int)version_len, (const char *)version);
    return 0;
invalid:
    fputs("Invalid app-info fields.\n", stderr);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "app-info") != 0) {
        fprintf(stderr, "Usage: %s app-info /dev/hidrawN\n", argv[0]);
        return 2;
    }
    int fd = open(argv[2], O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    struct hidraw_devinfo info;
    if (ioctl(fd, HIDIOCGRAWINFO, &info) < 0 || info.vendor != 0x2c97) {
        fputs("The selected HID device is not a Ledger device.\n", stderr);
        close(fd);
        return 1;
    }
    int result = show_app_info(fd);
    close(fd);
    return result;
}
