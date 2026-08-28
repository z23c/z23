/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "base/log_level.h"
#include "config/consensus_state_snapshot_install.h"
#include "platform/private_file.h"

#include <string.h>

enum zcl_log_level zcl_log_level_get(void) { return ZCL_LOG_ALL; }

int main(int argc, char **argv)
{
    if (argc != 2 || !platform_private_path_absent(argv[1]))
        return 2;
    struct consensus_state_snapshot_install_request request = {
        .bundle_path = argv[1],
    };
    struct consensus_state_install_result result;
    if (consensus_state_snapshot_install((struct sqlite3 *)(void *)&request,
                                         &request,
                                         &result) ||
        result.status != CONSENSUS_INSTALL_REFUSED ||
        !strstr(result.reason, "Windows consensus install refused") ||
        !platform_private_path_absent(argv[1]))
        return 3;
    struct consensus_state_artifact_evidence *evidence =
        (struct consensus_state_artifact_evidence *)(void *)&request;
    struct zcl_result opened = consensus_state_artifact_evidence_open(
        argv[1], -1, &evidence);
    return !opened.ok && evidence == NULL &&
                   platform_private_path_absent(argv[1])
               ? 0
               : 4;
}
