/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "ledger_hid.h"

#include <fcntl.h>
#include <glob.h>
#include <linux/hidraw.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static const char *model_name(unsigned int product) {
    switch (product) {
    case 0x0000: return "Ledger Blue";
    case 0x0004: return "Ledger Nano X";
    default: return "Ledger device";
    }
}

static void json_string(const uint8_t *value, size_t length) {
    putchar('"');
    for (size_t i = 0; i < length; ++i) {
        if (value[i] == '"' || value[i] == '\\') putchar('\\');
        putchar(value[i]);
    }
    putchar('"');
}

static int error_result(bool json, const char *code, const char *message) {
    if (json) printf("{\"ok\":false,\"error\":\"%s\"}\n", code);
    else fprintf(stderr, "%s\n", message);
    return 1;
}

static bool hidraw_path(const char *path) {
    static const char prefix[] = "/dev/hidraw";
    if (strncmp(path, prefix, sizeof prefix - 1) != 0) return false;
    const char *number = path + sizeof prefix - 1;
    if (!*number) return false;
    for (; *number; ++number) {
        if (*number < '0' || *number > '9') return false;
    }
    return true;
}

static int list_devices(bool json) {
    glob_t paths = {0};
    int scan = glob("/dev/hidraw*", 0, NULL, &paths);
    if (scan != 0 && scan != GLOB_NOMATCH) {
        globfree(&paths);
        return error_result(json, "device_scan_failed", "Cannot list HID devices.");
    }
    if (json) fputs("{\"ok\":true,\"devices\":[", stdout);
    size_t found = 0;
    for (size_t i = 0; i < paths.gl_pathc; ++i) {
        const char *path = paths.gl_pathv[i];
        if (!hidraw_path(path)) continue;
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        struct hidraw_devinfo info;
        int identified = ioctl(fd, HIDIOCGRAWINFO, &info);
        close(fd);
        if (identified < 0 || info.vendor != 0x2c97) continue;
        if (json) {
            if (found) putchar(',');
            fputs("{\"path\":", stdout);
            json_string((const uint8_t *)path, strlen(path));
            fputs(",\"model\":", stdout);
            const char *model = model_name((unsigned int)info.product);
            json_string((const uint8_t *)model, strlen(model));
            printf(",\"vendor_id\":\"%04x\",\"product_id\":\"%04x\"}",
                   (unsigned int)info.vendor, (unsigned int)info.product);
        } else {
            printf("%s  %s  (%04x:%04x)\n", path,
                   model_name((unsigned int)info.product),
                   (unsigned int)info.vendor, (unsigned int)info.product);
        }
        ++found;
    }
    if (json) fputs("]}\n", stdout);
    else if (!found) puts("No accessible Ledger HID interfaces found.");
    globfree(&paths);
    return 0;
}

static bool printable_ascii(const uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        if (data[i] < 0x20 || data[i] > 0x7e) return false;
    }
    return true;
}

static int show_app_info(int fd, bool json) {
    static const uint8_t command[] = {0xb0, 0x01, 0, 0, 0};
    uint8_t reply[LEDGER_HID_MAX_RESPONSE];
    size_t size;
    if (ledger_hid_exchange(fd, command, sizeof command, reply,
                            sizeof reply, &size) < 0)
        return error_result(json, "no_app_info_response",
                            "Ledger did not answer the read-only app-info command.");
    uint16_t status = (uint16_t)(((uint16_t)reply[size - 2] << 8) | reply[size - 1]);
    if (status != 0x9000) {
        if (json) printf("{\"ok\":false,\"error\":\"device_status\",\"status\":\"%04x\"}\n", status);
        else fprintf(stderr, "Ledger returned status %04x.\n", status);
        return 1;
    }
    size_t end = size - 2;
    if (end < 5 || reply[0] != 1)
        return error_result(json, "invalid_app_info", "Unexpected app-info format.");
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
    if (flags_len != end - pos || !printable_ascii(name, name_len) ||
        !printable_ascii(version, version_len)) goto invalid;
    if (json) {
        fputs("{\"ok\":true,\"name\":", stdout);
        json_string(name, name_len);
        fputs(",\"version\":", stdout);
        json_string(version, version_len);
        fputs("}\n", stdout);
    } else {
        printf("%.*s %.*s\n", (int)name_len, (const char *)name,
               (int)version_len, (const char *)version);
    }
    return 0;
invalid:
    return error_result(json, "invalid_app_info", "Invalid app-info fields.");
}

static int app_info(const char *path, bool json) {
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return error_result(json, "open_failed", "Cannot open the selected HID device.");
    struct hidraw_devinfo info;
    if (ioctl(fd, HIDIOCGRAWINFO, &info) < 0 || info.vendor != 0x2c97) {
        close(fd);
        return error_result(json, "not_ledger", "The selected HID device is not a Ledger device.");
    }
    int result = show_app_info(fd, json);
    close(fd);
    return result;
}

static int probe_info(const char *path, bool json) {
    static const uint8_t command[] = {0xa5, 0x01, 0, 0, 0};
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return error_result(json, "open_failed", "Cannot open the selected HID device.");
    struct hidraw_devinfo info;
    if (ioctl(fd, HIDIOCGRAWINFO, &info) < 0 || info.vendor != 0x2c97) {
        close(fd);
        return error_result(json, "not_ledger", "The selected HID device is not a Ledger device.");
    }
    uint8_t reply[LEDGER_HID_MAX_RESPONSE];
    size_t reply_len = 0;
    int exchanged = ledger_hid_exchange(fd, command, sizeof command, reply,
                                        sizeof reply, &reply_len);
    close(fd);
    if (exchanged < 0)
        return error_result(json, "no_probe_response", "ZCL Probe did not answer.");
    if (ledger_probe_parse(reply, reply_len) < 0)
        return error_result(json, "invalid_probe", "The running app is not ZCL Probe version 1.");
    if (json) puts("{\"ok\":true,\"protocol\":\"zcl-probe\",\"version\":1,\"address\":false,\"signing\":false}");
    else puts("ZCL Probe 1: address and signing unavailable");
    return 0;
}

int main(int argc, char **argv) {
    if ((argc == 2 || argc == 3) && strcmp(argv[1], "devices") == 0 &&
        (argc == 2 || strcmp(argv[2], "--json") == 0))
        return list_devices(argc == 3);
    if ((argc == 3 || argc == 4) && strcmp(argv[1], "app-info") == 0 &&
        (argc == 3 || strcmp(argv[2], "--json") == 0))
        return app_info(argv[argc - 1], argc == 4);
    if ((argc == 3 || argc == 4) && strcmp(argv[1], "probe") == 0 &&
        (argc == 3 || strcmp(argv[2], "--json") == 0))
        return probe_info(argv[argc - 1], argc == 4);
    fprintf(stderr, "Usage: %s devices [--json]\n"
                    "       %s app-info [--json] /dev/hidrawN\n"
                    "       %s probe [--json] /dev/hidrawN\n",
            argv[0], argv[0], argv[0]);
    return 2;
}
