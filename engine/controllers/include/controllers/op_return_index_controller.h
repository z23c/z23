/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * OP_RETURN catalog controller — native commands for the op_return_index
 * projection (engine/models/src/op_return_index.h): every OP_RETURN output
 * ever seen on the chain, tagged by its lokad-style prefix.
 *
 * Commands:
 *   oprindex_status   — cursor height/digest, provable tip, total rows,
 *                        rows-by-known-tag counts (ZNAM/ZSLP/ZANC/other)
 *   oprindex_list     — bounded list by tag and/or height range
 *   oprindex_rebuild  — drop-and-rederive entry point (op_return_index_
 *                        truncate); the backfill service re-derives from
 *                        block bodies on its next ticks */

#ifndef ZCL_CONTROLLERS_OP_RETURN_INDEX_H
#define ZCL_CONTROLLERS_OP_RETURN_INDEX_H

#include "rpc/server.h"
#include "models/database.h"

void rpc_op_return_index_set_state(struct node_db *ndb);
void register_op_return_index_rpc_commands(struct rpc_table *t);

#endif /* ZCL_CONTROLLERS_OP_RETURN_INDEX_H */
