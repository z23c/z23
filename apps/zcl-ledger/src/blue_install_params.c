/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_install_params.h"

#include <string.h>

size_t blue_install_params(const char *name, const char *version,
                           bool zcl_sign_path,
                           uint8_t output[ZCL_BLUE_INSTALL_PARAMS_MAX]) {
    if (!name || !version || !output) return 0;
    size_t name_length = strlen(name);
    if (name_length == 0 || name_length > 32 || strlen(version) != 5) return 0;
    size_t length = 0;
    output[length++] = 0x01;
    output[length++] = (uint8_t)name_length;
    memcpy(output + length, name, name_length);
    length += name_length;
    output[length++] = 0x02;
    output[length++] = 5;
    memcpy(output + length, version, 5);
    length += 5;
    static const uint8_t zcl_path[] = {
        0x01, 5,
        0x80, 0, 0, 0x2c,
        0x80, 0, 0, 0x93,
        0x80, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
    };
    output[length++] = 0x04;
    output[length++] = zcl_sign_path ? sizeof zcl_path : 1;
    if (zcl_sign_path) {
        memcpy(output + length, zcl_path, sizeof zcl_path);
        length += sizeof zcl_path;
    } else output[length++] = 0;
    return length;
}
