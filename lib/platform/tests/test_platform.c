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

    return 0;
}
