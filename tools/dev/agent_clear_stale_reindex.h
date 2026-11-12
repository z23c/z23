/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Clear a stale dev-lane auto_reindex_request after the lane
 *          serves at or above the marker anchor. */

#ifndef ZCL_AGENT_CLEAR_STALE_REINDEX_H
#define ZCL_AGENT_CLEAR_STALE_REINDEX_H

/* repo is the checkout whose build/bin/zclassic-cli is asked for height
 * and agent status. argv[0], when present, is text, json, or --json.
 * Returns 0 when the marker is absent, not pending, proven in a dry run,
 * or archived. Returns 1 when the proof refuses. Returns 2 for a missing
 * repo, a path that does not fit, or a mode other than text or json. */
int zcl_agent_clear_stale_reindex(const char *repo, int argc, char **argv);

#endif
