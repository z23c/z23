/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the bounds of one `dev land drive --prove` invocation that keeps
 *          draining the queue: how many rows it may take and the wall-clock
 *          budget after which it starts no further row.
 *
 * Split out of tools/command/native_dev_land.c (at its file-size ceiling).
 * The drain loop itself stays in dl_drive_rows; this file only answers "may
 * another row start". It never shortens or kills a row already running: the
 * budget is checked between rows, so the lock, the row's own proof and every
 * stop condition behave exactly as in a one-row drive.
 */
#ifndef ZCL_NATIVE_DEV_LAND_DRAIN_H
#define ZCL_NATIVE_DEV_LAND_DRAIN_H

#include <stdbool.h>
#include <stdint.h>

#include "command/native_command.h"

#define DL_DRIVE_MAX_ROWS 16

/* input.max_rows (1..DL_DRIVE_MAX_ROWS, default 1) and input.prove. */
bool dl_drain_rows_in(const struct zcl_command_request *req, int *rows,
                      bool *prove);

/* Monotonic deadline from ZCL_LAND_DRIVE_BUDGET_S (1..86400 seconds), or 0
 * when it is unset or malformed: no wall-clock bound beyond max_rows. */
int64_t dl_drain_deadline_ms(void);

/* May another row start: fewer than max_rows done and no passed deadline. */
bool dl_drain_more(int done, int max_rows, int64_t deadline_ms);

#endif
