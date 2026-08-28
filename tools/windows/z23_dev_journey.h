/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef Z23_TOOLS_WINDOWS_Z23_DEV_JOURNEY_H
#define Z23_TOOLS_WINDOWS_Z23_DEV_JOURNEY_H

#ifdef _WIN32
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum z23_dev_command {
    Z23_DEV_CREATE = 0,
    Z23_DEV_DEVELOP,
    Z23_DEV_SHIP
};

struct z23_dev_layout {
    wchar_t devkit_root[32768];
    wchar_t toolchain_bin[32768];
    wchar_t cmake[32768];
    wchar_t ninja[32768];
    wchar_t clang[32768];
};

struct z23_dev_step {
    const wchar_t *name;
    wchar_t executable[32768];
    wchar_t arguments[32768];
};

/* Resolve tools relative to z23-dev.exe. Ambient PATH and compiler discovery
 * are deliberately not part of this contract. */
bool z23_dev_layout_from_executable(const wchar_t *executable,
                                    struct z23_dev_layout *layout,
                                    char *error, size_t error_size);

/* Every executable must be a local, non-directory, non-reparse file before a
 * process is started. This prevents PATH fallback and junction substitution. */
bool z23_dev_layout_validate(const struct z23_dev_layout *layout,
                             char *error, size_t error_size);

size_t z23_dev_plan(enum z23_dev_command command,
                    const struct z23_dev_layout *layout,
                    struct z23_dev_step *steps, size_t capacity);

uint64_t z23_dev_elapsed_ms(int64_t start, int64_t finish, int64_t frequency);

#endif
#endif
