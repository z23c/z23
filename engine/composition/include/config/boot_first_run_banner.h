/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_first_run_banner — a short plain-English banner for a newcomer who
 * runs the node by hand. Presentation only: it calls no boot decision and
 * changes nothing about boot, sync, logging or what is downloaded. Printed
 * once, only when stdout is a terminal (never under systemd or a pipe), so
 * logs and services are unchanged. */

#ifndef ZCL_CONFIG_BOOT_FIRST_RUN_BANNER_H
#define ZCL_CONFIG_BOOT_FIRST_RUN_BANNER_H

#include <stdbool.h>
#include <stddef.h>

struct app_context;

/* Pure builder. Writes at most 4 lines into buf (NUL-terminated, cap bytes).
 * Returns the text length, or 0 (buf empty) when !is_tty, buf is NULL/cap is 0,
 * or the text does not fit. first_run (a datadir created by this boot) adds
 * a line saying the first sync takes a while. */
size_t boot_first_run_banner_text(char *buf, size_t cap, const char *datadir,
                                  bool first_run, bool is_tty);

/* Boot hook: decides is_tty (isatty(stdout)) and first_run (!datadir_existed),
 * then prints the banner to stdout. Also owns the one-line "Created data
 * directory" notice (all terminals and pipes). */
void boot_first_run_banner_print(const struct app_context *ctx,
                                 bool datadir_existed);

#endif
