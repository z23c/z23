/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Classify a confined action's captured report before it is judged. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_WORKER_REPORT_H
#define ZCL_SERVICES_BUILD_FABRIC_WORKER_REPORT_H

#include <stddef.h>

/* What a failed confined action's captured report actually says. The two
 * process-accounting outcomes are NOT build verdicts and must never reach a
 * log looking like one:
 *
 *   HEADROOM — the HOST had no process table left for this uid. Retryable;
 *              says nothing about the input. RLIMIT_NPROC is charged per
 *              real uid, so this is a property of everything else the
 *              account is running (see platform/os_sandbox.h).
 *   BUDGET   — the confined subtree held more processes than the action
 *              declares. A defect in the input; never retry it.
 *
 * This distinction is the whole point: a fork EAGAIN reaches the compiler's
 * stderr as its own fatal error, so before this classification a busy host
 * and a broken source file produced the same line. */
enum build_fabric_report_class {
    BUILD_FABRIC_REPORT_OTHER = 0,
    BUILD_FABRIC_REPORT_PROCESS_HEADROOM,
    BUILD_FABRIC_REPORT_PROCESS_BUDGET,
};

/* Classify `capture`, then SANITIZE it in place to printable ASCII, log the
 * classification when it is one of the process outcomes, and write the
 * failure detail for the action's named outcome into `detail`.
 *
 * Classification runs BEFORE sanitizing (the markers are plain ASCII), and
 * the verifier's own line — which carries the installed limit, the uid task
 * count at admission, the uid task count now, and the subtree budget and
 * peak — is carried through verbatim. `rc` is the spawn return code. */
enum build_fabric_report_class build_fabric_worker_classify_report(
    char *capture, int rc, char *detail, size_t detail_cap);

#endif /* ZCL_SERVICES_BUILD_FABRIC_WORKER_REPORT_H */
