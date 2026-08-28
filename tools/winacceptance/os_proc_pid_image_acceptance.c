/* Headless acceptance for handle-bound Windows process image discovery. */
#include "platform/os_proc.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
int main(void)
{
    char self[32768], queried[32768];
    uint64_t pid = os_proc_current_pid();
    if (!os_proc_exe_path(self, sizeof(self)) ||
        !os_proc_pid_exe_path(pid, queried, sizeof(queried)) ||
        _stricmp(self, queried) != 0 ||
        os_proc_pid_exe_path(0, queried, sizeof(queried)))
        return 1;
    puts("os_proc_pid_image_acceptance: PASS");
    return 0;
}
#else
int main(void) { return 77; }
#endif
