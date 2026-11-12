/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Report whether this checkout's Git pre-push hook is armed. */

#ifndef ZCL_HOOKS_STATUS_H
#define ZCL_HOOKS_STATUS_H

/* Prints the make hooks-status report for root. A NULL or empty root uses
 * ZCL_HOOKS_STATUS_ROOT, then the checkout that holds this binary. The
 * report never installs a hook and always returns 0. */
int zcl_hooks_status(const char *root);

#endif
