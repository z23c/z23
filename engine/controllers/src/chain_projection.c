/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/chain_projection.h"

#include "controllers/rpc_client.h"
#include "util/log_macros.h"
#include "util/path_check.h"
#include "util/projection.h"

#include <stdint.h>

static int64_t chain_projection_query_i64(const char *label, const char *sql)
{
    const char *datadir = node_rpc_client_datadir();
    if (!datadir || !datadir[0])
        LOG_RETURN(-1, "chain_projection", "%s: RPC datadir is unset", label);

    char db_path[1024];
    zcl_node_db_path(db_path, sizeof(db_path), datadir);

    projection_t *p = projection_open(db_path);
    if (!p)
        LOG_RETURN(-1, "chain_projection", "%s: projection open failed", label);

    int64_t v = -1;
    if (projection_query_int64(p, sql, &v) != 0)
        LOG_ERR("chain_projection", "query miss label=%s sql=%s",
                label ? label : "(null)", sql ? sql : "(null)");
    projection_close(p);
    return v;
}

int64_t chain_projection_best_block_height(void)
{
    return chain_projection_query_i64(
        "chain.best_block_height",
        "SELECT COALESCE(MAX(height), -1) FROM blocks WHERE status>=3");
}

int64_t chain_projection_best_header_height(void)
{
    return chain_projection_query_i64(
        "chain.best_header_height",
        "SELECT COALESCE(MAX(height), -1) FROM blocks");
}
