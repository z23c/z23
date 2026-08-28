/* Headless acceptance: Windows binary-slot mutation refuses before I/O. */
#include "platform/os_binary_slots.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

int main(void)
{
    char slots[256];
    (void)snprintf(slots, sizeof(slots),
                   "build/os-binary-slots-refusal-%lu",
                   (unsigned long)GetCurrentProcessId());
    if (GetFileAttributesA(slots) != INVALID_FILE_ATTRIBUTES)
        return 1;

    char error[OS_BINARY_SLOTS_ERROR_MAX];
    if (os_binary_slots_ensure_directory(slots, error, sizeof(error)) ||
        strstr(error, "disabled on Windows") == NULL)
        return 2;
    if (GetFileAttributesA(slots) != INVALID_FILE_ATTRIBUTES)
        return 3;

    struct os_binary_slots_launch launch;
    if (os_binary_slots_prepare_launch(slots, "untrusted.exe", 3,
                                       &launch) ||
        launch.executable_fd != -1 || launch.streak_written ||
        strstr(launch.error, "disabled on Windows") == NULL)
        return 4;
    os_binary_slots_close_launch(&launch);

    if (os_binary_slots_reset_streak_file("must-not-exist", error,
                                          sizeof(error)) ||
        os_binary_slots_increment_streak_file("must-not-exist", error,
                                              sizeof(error)))
        return 5;
    if (GetFileAttributesA(slots) != INVALID_FILE_ATTRIBUTES)
        return 6;

    uint32_t threshold = 0;
    if (!os_binary_slots_parse_threshold("3", &threshold) || threshold != 3 ||
        os_binary_slots_parse_threshold("0", &threshold))
        return 7;
    puts("os_binary_slots_refusal_acceptance: PASS");
    return 0;
}
