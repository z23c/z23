/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "z23_dev_journey.h"

#ifdef _WIN32
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static int require(int condition, const char *message)
{
    if (condition)
        return 0;
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

int main(void)
{
    struct z23_dev_layout layout;
    struct z23_dev_step steps[3];
    char error[160];
    int failures = 0;
    size_t count;

    failures += require(z23_dev_layout_from_executable(
        L"C:\\kits\\z23-devkit-1.0\\z23-dev.exe", &layout,
        error, sizeof(error)), "resolve executable-relative devkit");
    failures += require(wcscmp(layout.devkit_root,
        L"C:\\kits\\z23-devkit-1.0") == 0, "exact devkit root");
    failures += require(wcscmp(layout.clang,
        L"C:\\kits\\z23-devkit-1.0\\toolchain\\bin\\clang.exe") == 0,
        "absolute bundled clang");
    failures += require(!z23_dev_layout_validate(&layout, error, sizeof(error)),
                        "missing bundled tools fail closed");
    failures += require(strstr(error, "cmake.exe") != NULL,
                        "missing tool error names exact prerequisite");

    count = z23_dev_plan(Z23_DEV_CREATE, &layout, steps, 3);
    failures += require(count == 1 && wcscmp(steps[0].name, L"create") == 0,
                        "one create step");
    count = z23_dev_plan(Z23_DEV_DEVELOP, &layout, steps, 3);
    failures += require(count == 2 && wcscmp(steps[0].executable,
                        layout.cmake) == 0, "develop uses bundled cmake");
    failures += require(wcsstr(steps[0].arguments, L"Ninja") != NULL,
                        "develop selects Ninja without discovery");
    failures += require(wcsstr(steps[0].arguments, layout.clang) != NULL &&
                        wcsstr(steps[0].arguments, layout.ninja) != NULL,
                        "develop pins compiler and build tool by absolute path");
    count = z23_dev_plan(Z23_DEV_SHIP, &layout, steps, 3);
    failures += require(count == 3 && wcscmp(steps[2].name, L"package") == 0,
                        "ship includes packaging");
    failures += require(z23_dev_plan(Z23_DEV_SHIP, &layout, steps, 2) == 0,
                        "insufficient plan storage fails closed");
    failures += require(z23_dev_elapsed_ms(100, 2600, 1000) == 2500,
                        "whole-second telemetry");
    failures += require(z23_dev_elapsed_ms(0, 1, 3) == 333,
                        "fractional telemetry");
    failures += require(z23_dev_elapsed_ms(10, 9, 1000) == 0,
                        "invalid telemetry fails closed");

    if (failures == 0)
        puts("Windows create/develop/ship journey: PASS");
    return failures != 0;
}
#else
int main(void) { return 0; }
#endif
