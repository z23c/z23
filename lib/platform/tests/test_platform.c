#include "platform/os_proc.h"
#include "platform/file_compat.h"
#include "platform/socket_compat.h"

#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

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

    platform_socket_t socket_handle =
        platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (socket_handle == PLATFORM_SOCKET_INVALID ||
        platform_socket_close(socket_handle) != 0)
        return 4;

    const char *file_path = "z23-platform-file-test.tmp";
    int first = platform_file_open_nofollow(file_path,
                                            O_RDWR | O_CREAT, 0600);
    int second = platform_file_open_nofollow(file_path, O_RDWR, 0600);
    const char payload[] = "z23-platform-file";
    unsigned char observed_payload[sizeof(payload)] = { 0 };
    if (first < 0 || second < 0 ||
        write(first, payload, sizeof(payload)) != (ssize_t)sizeof(payload) ||
        platform_file_pread(first, observed_payload, sizeof(observed_payload),
                            0) != (ssize_t)sizeof(observed_payload) ||
        memcmp(payload, observed_payload, sizeof(payload)) != 0 ||
        platform_file_lock_exclusive(first) != 0 ||
        platform_file_lock_exclusive(second) == 0 ||
        platform_file_unlock(first) != 0) {
        if (first >= 0) close(first);
        if (second >= 0) close(second);
        unlink(file_path);
        return 5;
    }
    const unsigned char *mapped = mmap(NULL, 3, PROT_READ, MAP_PRIVATE,
                                       first, 1);
    if (mapped == MAP_FAILED || memcmp(mapped, "23-", 3) != 0 ||
        munmap((void *)mapped, 3) != 0) {
        close(first);
        close(second);
        unlink(file_path);
        return 7;
    }
    close(first);
    close(second);
    if (unlink(file_path) != 0)
        return 6;
#if defined(_WIN32)
    if (handles_before != handles_after)
        return 3;
#endif
    return 0;
}
