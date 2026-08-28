/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: fail-closed Windows boundary for consensus publication I/O. */

#include "services/consensus_state_publication_cas.h"

#if defined(_WIN32)
#ifdef ZCL_TESTING
struct zcl_result consensus_state_publication_cas_persist_for_test(
    int dir_fd, const char *name,
    const struct consensus_state_publication_decision_record *record)
{
    (void)dir_fd;
    (void)name;
    (void)record;
    return ZCL_ERR(-47, "cas persist: native Windows directory capability "
                        "is unavailable");
}
#endif

struct zcl_result consensus_state_publication_cas_load(
    int dir_fd, const char *name,
    struct consensus_state_publication_decision_record *out_record)
{
    (void)dir_fd;
    (void)name;
    (void)out_record;
    return ZCL_ERR(-56, "cas load: native Windows directory capability "
                        "is unavailable");
}

struct zcl_result consensus_state_publication_cas_run(
    const struct consensus_state_publication_cas_request *request,
    struct consensus_state_publication_decision_record *out_record)
{
    (void)request;
    (void)out_record;
    return ZCL_ERR(-67, "cas run: native Windows directory capability "
                        "is unavailable");
}
#endif
