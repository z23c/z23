/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "z23_dev_journey.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdio.h>
#include <string.h>
#include <wchar.h>

static void set_error(char *error, size_t size, const char *message)
{
    if (error != NULL && size != 0)
        (void)snprintf(error, size, "%s", message);
}

static bool append(wchar_t *destination, size_t capacity, const wchar_t *suffix)
{
    size_t used = wcslen(destination);
    size_t extra = wcslen(suffix);
    if (used > capacity || extra >= capacity - used)
        return false;
    memcpy(destination + used, suffix, (extra + 1) * sizeof(*destination));
    return true;
}

static bool parent_directory(wchar_t *path)
{
    wchar_t *slash = wcsrchr(path, L'\\');
    wchar_t *forward = wcsrchr(path, L'/');
    if (forward != NULL && (slash == NULL || forward > slash))
        slash = forward;
    if (slash == NULL || slash == path)
        return false;
    *slash = L'\0';
    return true;
}

bool z23_dev_layout_from_executable(const wchar_t *executable,
                                    struct z23_dev_layout *layout,
                                    char *error, size_t error_size)
{
    wchar_t resolved[32768];
    DWORD count;

    if (executable == NULL || layout == NULL || executable[0] == L'\0') {
        set_error(error, error_size, "missing controller executable path");
        return false;
    }
    count = GetFullPathNameW(executable, (DWORD)(sizeof(resolved) /
                             sizeof(resolved[0])), resolved, NULL);
    if (count == 0 || count >= sizeof(resolved) / sizeof(resolved[0]) ||
        !parent_directory(resolved)) {
        set_error(error, error_size, "controller path has no devkit directory");
        return false;
    }
    memset(layout, 0, sizeof(*layout));
    if (wcslen(resolved) >= sizeof(layout->devkit_root) /
        sizeof(layout->devkit_root[0])) {
        set_error(error, error_size, "devkit root path is too long");
        return false;
    }
    wcscpy(layout->devkit_root, resolved);
    wcscpy(layout->toolchain_bin, resolved);
    if (!append(layout->toolchain_bin, 32768, L"\\toolchain\\bin"))
        goto too_long;
    wcscpy(layout->cmake, layout->toolchain_bin);
    wcscpy(layout->ninja, layout->toolchain_bin);
    wcscpy(layout->clang, layout->toolchain_bin);
    if (!append(layout->cmake, 32768, L"\\cmake.exe") ||
        !append(layout->ninja, 32768, L"\\ninja.exe") ||
        !append(layout->clang, 32768, L"\\clang.exe"))
        goto too_long;
    return true;

too_long:
    set_error(error, error_size, "devkit tool path is too long");
    return false;
}

static bool trusted_tool_file(const wchar_t *path)
{
    DWORD attributes = GetFileAttributesW(path);
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}

bool z23_dev_layout_validate(const struct z23_dev_layout *layout,
                             char *error, size_t error_size)
{
    if (layout == NULL) {
        set_error(error, error_size, "missing devkit layout");
        return false;
    }
    if (!trusted_tool_file(layout->cmake)) {
        set_error(error, error_size, "bundled cmake.exe is missing or unsafe");
        return false;
    }
    if (!trusted_tool_file(layout->ninja)) {
        set_error(error, error_size, "bundled ninja.exe is missing or unsafe");
        return false;
    }
    if (!trusted_tool_file(layout->clang)) {
        set_error(error, error_size, "bundled clang.exe is missing or unsafe");
        return false;
    }
    return true;
}

static bool set_step(struct z23_dev_step *step, const wchar_t *name,
                     const wchar_t *executable, const wchar_t *arguments)
{
    if (wcslen(executable) >= 32768 || wcslen(arguments) >= 32768)
        return false;
    step->name = name;
    wcscpy(step->executable, executable);
    wcscpy(step->arguments, arguments);
    return true;
}

size_t z23_dev_plan(enum z23_dev_command command,
                    const struct z23_dev_layout *layout,
                    struct z23_dev_step *steps, size_t capacity)
{
    wchar_t configure[32768];
    const wchar_t *build_dir;
    const wchar_t *build_type;
    int written;

    if (layout == NULL || steps == NULL)
        return 0;
    if (command == Z23_DEV_CREATE) {
        if (capacity < 1 || !set_step(&steps[0], L"create",
            L"<controller>", L"scaffold native-gui-c23"))
            return 0;
        return 1;
    }
    if (command == Z23_DEV_DEVELOP || command == Z23_DEV_SHIP) {
        build_dir = command == Z23_DEV_DEVELOP ?
                    L".z23\\build\\develop" : L".z23\\build\\ship";
        build_type = command == Z23_DEV_DEVELOP ? L"Debug" : L"Release";
        written = swprintf(configure, sizeof(configure) / sizeof(configure[0]),
            L"%ls-S . -B %ls -G Ninja -DCMAKE_BUILD_TYPE=%ls "
            L"-DCMAKE_C_COMPILER=\"%ls\" -DCMAKE_MAKE_PROGRAM=\"%ls\"",
            command == Z23_DEV_SHIP ? L"--fresh " : L"",
            build_dir, build_type, layout->clang, layout->ninja);
        if (written < 0 || (size_t)written >=
            sizeof(configure) / sizeof(configure[0]))
            return 0;
    }
    if (command == Z23_DEV_DEVELOP) {
        if (capacity < 2 ||
            !set_step(&steps[0], L"configure", layout->cmake, configure) ||
            !set_step(&steps[1], L"build", layout->cmake,
              L"--build .z23\\build\\develop --parallel"))
            return 0;
        return 2;
    }
    if (command == Z23_DEV_SHIP) {
        if (capacity < 3 ||
            !set_step(&steps[0], L"configure-release", layout->cmake,
              configure) ||
            !set_step(&steps[1], L"build-release", layout->cmake,
              L"--build .z23\\build\\ship --parallel") ||
            !set_step(&steps[2], L"package", layout->cmake,
              L"--build .z23\\build\\ship --target package"))
            return 0;
        return 3;
    }
    return 0;
}

uint64_t z23_dev_elapsed_ms(int64_t start, int64_t finish, int64_t frequency)
{
    uint64_t ticks;
    if (finish <= start || frequency <= 0)
        return 0;
    ticks = (uint64_t)(finish - start);
    return (ticks / (uint64_t)frequency) * UINT64_C(1000) +
           ((ticks % (uint64_t)frequency) * UINT64_C(1000)) /
           (uint64_t)frequency;
}
#endif
