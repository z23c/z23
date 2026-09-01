/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Emit bounded metrics derived from canonical async-proof facts. */

#include "config/boot_zcode_work_perf.h"

#include "base/hex.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "vcs/package_swarm_node.h"

void boot_zcode_work_perf_admission(
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_package_store_status *status,
    struct vcs_swarm_engine *engine, int64_t admission_us)
{
    if (!request || !status) return;
    struct vcs_swarm_download_status download = {0};
    bool have_download = engine && vcs_swarm_engine_download_status(
        engine, request->context_root, &download);
    char action_id[65];
    zcl_hex_encode(request->action_root, 32, action_id);
    LOG_INFO("zcode.proof_perf",
             "schema=zcl.async_proof_perf.v1 action=%s "
             "stage=remote_admission at_unix_us=%lld admission_us=%lld "
             "context_bytes=%llu transferred_bytes=%llu context_cache_hit=%d",
             action_id, (long long)platform_time_realtime_us(),
             (long long)(admission_us < 0 ? 0 : admission_us),
             (unsigned long long)status->total_bytes,
             (unsigned long long)(have_download ? download.fetched_bytes : 0),
             have_download && download.fetched_bytes == 0 ? 1 : 0);
}
