/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: read verified source members from the currently kept Tasks package. */
#ifndef ZCL_NATIVE_APP_CUSTOMIZE_TASKS_H
#define ZCL_NATIVE_APP_CUSTOMIZE_TASKS_H
#include "models/package_resident.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct ac_tasks_file {
    struct package_resident_record kept;
    uint8_t *bytes;
    size_t size;
    uint32_t mode;
};
/* Read the current resident record without modifying the profile. */
bool ac_tasks_kept_read(const char *directory, struct package_resident_record *out);
/* Read only the exact current resident package; caller frees bytes. */
bool ac_tasks_file_read(const char *directory, const char *root, uint64_t generation,
                        const char *path, struct ac_tasks_file *out);
#endif
