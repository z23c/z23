/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_first_run_banner.c — see config/boot_first_run_banner.h. */
#include "config/boot_first_run_banner.h"

#include "config/boot.h"

#include <limits.h>
#include <stdio.h>
#include <unistd.h>

#define BANNER_GUIDE_URL "https://z23.sh/start"

size_t boot_first_run_banner_text(char *buf, size_t cap, const char *datadir,
                                  bool first_run, bool is_tty)
{
    if (!buf || cap == 0)
        return 0;
    buf[0] = '\0';
    if (!is_tty)
        return 0;
    int n = snprintf(buf, cap,
                     "Z23 node starting (data in %s).\n"
                     "%s"
                     "Leave this running; in another terminal run: z23 status\n"
                     "Stop with Ctrl-C. Guide: " BANNER_GUIDE_URL "\n",
                     (datadir && datadir[0]) ? datadir : "the default data directory",
                     first_run ? "First run: the first sync takes a while; "
                                 "z23 status shows how far it is.\n"
                               : "");
    if (n < 0 || (size_t)n >= cap) {
        buf[0] = '\0';
        return 0;
    }
    return (size_t)n;
}

void boot_first_run_banner_print(const struct app_context *ctx,
                                 bool datadir_existed)
{
    if (ctx && !datadir_existed)
        printf("Created data directory: %s\n", ctx->datadir);
    if (!ctx || isatty(STDOUT_FILENO) != 1)
        return;
    char text[PATH_MAX + 320];
    if (boot_first_run_banner_text(text, sizeof(text), ctx->datadir,
                                   !datadir_existed, true) > 0) {
        fputs(text, stdout);
        fflush(stdout);
    }
}
