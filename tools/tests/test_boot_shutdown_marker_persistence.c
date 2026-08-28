/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Verify clean-shutdown markers persist privately and atomically. */
#include "config/boot_shutdown_marker.h"
#include "base/log_level.h"
#include "event/event.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"

#include <stdarg.h>
#include <stdio.h>

enum zcl_log_level zcl_log_level_get(void)
{
    return ZCL_LOG_ALL;
}

void event_emitf(enum event_type type, uint32_t peer_id, const char *fmt, ...)
{
    (void)type;
    (void)peer_id;
    (void)fmt;
}

int main(int argc, char **argv)
{
    if (argc != 2 || !platform_private_directory_ensure(argv[1]))
        return 2;
    char marker[1024];
    if (snprintf(marker, sizeof(marker), "%s/.shutdown_clean", argv[1]) <= 0)
        return 3;
    if (!boot_shutdown_marker_write_clean(argv[1]))
        return 4;
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    bool private_marker = platform_positioned_file_open(&file, marker) &&
                          platform_positioned_file_is_private(&file);
    platform_positioned_file_close(&file);
    if (!private_marker || boot_shutdown_marker_detect_unclean(argv[1]) ||
        !platform_private_path_absent(marker))
        return 5;
    if (!boot_shutdown_marker_write_clean(argv[1]) ||
        !boot_shutdown_marker_remove_clean(argv[1]) ||
        !platform_private_path_absent(marker))
        return 6;
    return 0;
}
