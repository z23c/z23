/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Record one self-contained two-node netdisrupt drill on the
 *          shared stopwatch ledger. */

#ifndef ZCL_NETDISRUPT_TWO_NODE_RECORD_H
#define ZCL_NETDISRUPT_TWO_NODE_RECORD_H

/* Runs drill (or the checkout's two-node drill when drill is NULL) once,
 * appends one history.jsonl line under history_dir (or ZCL_ND_HISTORY_DIR,
 * or the default stopwatch directory), then returns 0 for pass and skip.
 * Other drill statuses propagate. 1 when the ledger cannot be appended. */
int zcl_netdisrupt_two_node_record(const char *repo, const char *drill,
                                   const char *history_dir);

#endif
