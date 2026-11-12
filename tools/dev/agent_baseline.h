/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Emit the lane baseline pin as stable key=value lines. */

#ifndef ZCL_AGENT_BASELINE_H
#define ZCL_AGENT_BASELINE_H

/* Prints the pin for repo (or this checkout when repo is NULL). files are
 * the pinned paths when argc > 0; otherwise BASELINE_FILES is split on
 * whitespace. Returns 0 when every pin was derived, 1 when a named file is
 * missing, the test-group counter failed, or the lint-gate counts disagree.
 * A missing Makefile or a failed digest tool returns that tool's status. */
int zcl_agent_baseline(const char *repo, int argc, char **files);

#endif
