/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Retain bounded first-attempt diagnostics in a proof attempt. */
#ifndef ZCL_DEV_PROOF_RETRY_EVIDENCE_H
#define ZCL_DEV_PROOF_RETRY_EVIDENCE_H
#include <stddef.h>
enum zcl_retry_evidence_status { ZCL_RETRY_EVIDENCE_NONE, ZCL_RETRY_EVIDENCE_COMPLETE,
    ZCL_RETRY_EVIDENCE_PARTIAL, ZCL_RETRY_EVIDENCE_UNAVAILABLE };
struct zcl_retry_evidence_result {
    enum zcl_retry_evidence_status status;
    size_t observed, retained, missing, errors;
};
/* Best effort; inputs name one exact proof generation and its private attempt.
 * Does not change the test verdict. */
struct zcl_retry_evidence_result zcl_dev_proof_retry_evidence(
    const char *generation, const char *test_log, const char *attempt_logs,
    const char *selected_groups);
void zcl_dev_proof_retry_evidence_report(const char *generation, const char *logs,
    const char *key, const char *selected_groups, const char *phases);
#if defined(ZCL_TESTING) && !defined(_WIN32)
void zcl_dev_proof_retry_test_after_copy(void (*hook)(void *), void *context);
#endif
#endif
