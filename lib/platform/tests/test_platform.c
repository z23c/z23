#include "platform/os_proc.h"

#include <stdint.h>

int main(void)
{
    const struct os_proc_mem expected = {
        .rss_bytes = 11, .vsize_bytes = 22,
        .cgroup_current = 33, .cgroup_high = 44, .cgroup_max = 55,
        .sys_total_bytes = 66, .sys_avail_bytes = 77,
    };
    struct os_proc_mem observed;
    os_proc_mem_set_override(&expected);
    bool ok = os_proc_mem_read(&observed);
    os_proc_mem_set_override(NULL);
    if (!ok || observed.rss_bytes != 11 || observed.cgroup_max != 55 ||
        observed.sys_avail_bytes != 77)
        return 1;

    char executable[4096];
    size_t handles_before = 0;
    size_t handles_after = 0;
    if (!os_proc_mem_read(&observed) || observed.rss_bytes < 0 ||
        !os_proc_exe_path(executable, sizeof(executable)) ||
        executable[0] == '\0' || os_proc_uptime_seconds() < 0 ||
        !os_proc_cmdline_has_token("z23-platform-self-token") ||
        os_proc_cmdline_has_token("z23-platform-self-token-suffix") ||
        !os_proc_open_fd_count(&handles_before) ||
        !os_proc_open_fd_count(&handles_after))
        return 2;
#if defined(_WIN32)
    if (handles_before != handles_after)
        return 3;
#endif
    return 0;
}
