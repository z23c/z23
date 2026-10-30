/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declarations for the check_quality_lane_freshness port: git runner
 * (fork plus execvp, no shell), the freshness report, and the check and
 * refresh drivers. Used by gate_quality_lane_freshness.c and its selftest.
 */
#ifndef GATE_QUALITY_LANE_FRESHNESS_PRIV_H
#define GATE_QUALITY_LANE_FRESHNESS_PRIV_H

#include <stdio.h>
#include <stddef.h>

#define QF_PATH 1024
#define QF_LINE 512
#define QF_SHA 64

int qf_git(const char *root, char **args, char *out, size_t cap, size_t *olen);
int qf_report(const char *root, const char *ref, char *line, size_t cap,
              FILE *err);
int qf_do_check(const char *root, const char *ref, FILE *out, FILE *err);
int qf_do_refresh(const char *root, const char *ref, FILE *out, FILE *err);

#endif
