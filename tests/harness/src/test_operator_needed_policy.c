/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_operator_needed_policy — pins the ONE table that decides whether a
 * node status reason means an operator has to intervene
 * (engine/controllers/include/controllers/operator_needed_policy.def).
 *
 * WHY THIS EXISTS: the public REST status endpoint
 * (engine/controllers/src/api_controller_status.c) and the agent first-call
 * summary (cognition/controllers/src/event_agent_summary.c) each used to carry their
 * own inline if/else-if ladder assigning `operator_needed`, plus their own
 * copies of every rung's `status` and `summary` string. The node could
 * therefore give two different answers to "does an operator need to act". The
 * two ladders had already drifted: the agent ladder observes four signals the
 * REST ladder does not (peer-telemetry availability, catch-up stall,
 * download-dispatch stall, projection lag).
 *
 * The consolidation is behaviour-PRESERVING: every expected value below was
 * transcribed from the two inline ladders as they stood on the parent commit,
 * so this file is the golden that says the extraction changed nothing an
 * operator reads. It is also the file that fails if someone later flips a
 * verdict in the .def without meaning to.
 *
 * The two assertions worth reading twice:
 *   - PEER_SNAPSHOT_BUSY must stay operator_needed=false EVEN WITH WARNINGS
 *     PRESENT. That rung exists so a momentarily-contended peer snapshot
 *     (peer_count UNKNOWN, not zero) cannot fall through to NO_PEERS and page
 *     an operator about peers that were never counted. Flipping it to true
 *     manufactures a false page on every busy telemetry read.
 *   - exactly ONE reason's verdict may depend on warning_count
 *     (HEALTHCHECK_UNHEALTHY). If a second reason starts varying with the
 *     count, the "does an operator need to act" question has grown a second
 *     input and the ladder is drifting again. */

#include "test/test_core.h"

#include "controllers/operator_needed_policy.h"

#include <stdio.h>
#include <string.h>

#define ONP_CHECK(name, expr) do {                                \
    printf("operator_needed_policy: %s... ", (name));             \
    if (expr) { printf("OK\n"); }                                 \
    else { printf("FAIL\n"); failures++; }                        \
} while (0)

/* The golden table, transcribed from the two inline ladders on the parent
 * commit. Deliberately hand-written and NOT generated from the .def: a golden
 * derived from the thing it checks proves nothing. */
struct onp_expect {
    enum node_status_reason reason;
    const char *name;
    const char *status;
    const char *summary;
    bool needed_no_warnings;   /* warning_count == 0 */
    bool needed_with_warnings; /* warning_count == 3 */
};

static const struct onp_expect g_expect[] = {
    { ZCL_STATUS_REASON_NONE, "NONE", "healthy",
      "node healthy at served frontier", false, false },
    { ZCL_STATUS_REASON_TYPED_BLOCKER, "TYPED_BLOCKER", "blocked",
      "node is held by an authoritative typed blocker", true, true },
    { ZCL_STATUS_REASON_POSTURE_REVIEW, "POSTURE_REVIEW", "blocked",
      "consensus-state trust posture requires review", true, true },
    { ZCL_STATUS_REASON_HEALTH_BLOCKER, "HEALTH_BLOCKER", "blocked",
      "node has an active health blocker", true, true },
    { ZCL_STATUS_REASON_NOT_SERVING, "NOT_SERVING", "blocked",
      "node is not serving", true, true },
    { ZCL_STATUS_REASON_PEER_SNAPSHOT_BUSY, "PEER_SNAPSHOT_BUSY", "degraded",
      "node peer telemetry is temporarily busy", false, false },
    { ZCL_STATUS_REASON_NO_PEERS, "NO_PEERS", "blocked",
      "node has no connected peers", true, true },
    { ZCL_STATUS_REASON_CATCHUP_STALLED, "CATCHUP_STALLED", "degraded",
      "node is behind and catch-up has not advanced recently", true, true },
    { ZCL_STATUS_REASON_DOWNLOAD_DISPATCH_IDLE, "DOWNLOAD_DISPATCH_IDLE",
      "degraded", "node has queued block downloads but no in-flight requests",
      true, true },
    { ZCL_STATUS_REASON_CHAIN_GAP_DOWNLOADING, "CHAIN_GAP_DOWNLOADING",
      "catching_up", "node is downloading blocks toward the best known tip",
      false, false },
    { ZCL_STATUS_REASON_DOWNLOAD_QUEUE_IDLE, "DOWNLOAD_QUEUE_IDLE", "degraded",
      "node is behind the best known tip without active downloads", true,
      true },
    { ZCL_STATUS_REASON_PROJECTION_LAG, "PROJECTION_LAG", "degraded",
      "node block projection is behind the served frontier", false, false },
    { ZCL_STATUS_REASON_HEALTHCHECK_UNHEALTHY, "HEALTHCHECK_UNHEALTHY",
      "degraded", "node health checks are degraded", false, true },
};

static const size_t g_expect_n = sizeof(g_expect) / sizeof(g_expect[0]);

/* Every reason the .def declares must appear in the golden above, and the
 * golden must not name one that no longer exists. Without this, adding a .def
 * row silently escapes every assertion in this file. */
static int case_table_is_complete(void)
{
    int failures = 0;
    char msg[192];

    snprintf(msg, sizeof(msg),
             "golden covers every enum reason (golden %zu, enum %d)",
             g_expect_n, (int)ZCL_STATUS_REASON__COUNT);
    ONP_CHECK(msg, g_expect_n == (size_t)ZCL_STATUS_REASON__COUNT);

    /* Positional identity: golden row i must BE reason i, so a reordered .def
     * cannot quietly re-point a golden row at a different rung. */
    bool aligned = true;
    for (size_t i = 0; i < g_expect_n; i++) {
        if ((int)g_expect[i].reason != (int)i) {
            printf("operator_needed_policy: golden row %zu is reason %d\n", i,
                   (int)g_expect[i].reason);
            aligned = false;
        }
        if (strcmp(node_status_reason_name(g_expect[i].reason),
                   g_expect[i].name) != 0) {
            printf("operator_needed_policy: reason %zu name is '%s', golden "
                   "says '%s'\n", i,
                   node_status_reason_name(g_expect[i].reason),
                   g_expect[i].name);
            aligned = false;
        }
    }
    ONP_CHECK("golden rows are positionally aligned with the enum", aligned);
    return failures;
}

static int case_truth_table(void)
{
    int failures = 0;
    char msg[256];

    for (size_t i = 0; i < g_expect_n; i++) {
        const struct onp_expect *e = &g_expect[i];

        snprintf(msg, sizeof(msg), "%s status is '%s'", e->name, e->status);
        ONP_CHECK(msg,
                  strcmp(node_status_reason_status(e->reason), e->status) == 0);

        snprintf(msg, sizeof(msg), "%s summary is unchanged wording",
                 e->name);
        ONP_CHECK(msg, strcmp(node_status_reason_summary(e->reason),
                              e->summary) == 0);

        snprintf(msg, sizeof(msg), "%s operator_needed=%s with 0 warnings",
                 e->name, e->needed_no_warnings ? "true" : "false");
        ONP_CHECK(msg,
                  node_status_reason_operator_needed(e->reason, 0) ==
                      e->needed_no_warnings);

        snprintf(msg, sizeof(msg), "%s operator_needed=%s with 3 warnings",
                 e->name, e->needed_with_warnings ? "true" : "false");
        ONP_CHECK(msg,
                  node_status_reason_operator_needed(e->reason, 3) ==
                      e->needed_with_warnings);
    }
    return failures;
}

/* The peer-telemetry-busy rung is the one place the two parent ladders
 * genuinely disagreed (the agent summary had it; the REST status endpoint had
 * no such observation to make). It is deliberately NOT operator_needed, and it
 * must stay that way regardless of warning count: the whole point is that a
 * contended peer read leaves peer_count UNKNOWN rather than zero, so escalating
 * would page an operator about peers nobody counted. */
static int case_peer_snapshot_busy_never_pages(void)
{
    int failures = 0;
    ONP_CHECK("PEER_SNAPSHOT_BUSY does not page at 0 warnings",
              node_status_reason_operator_needed(
                  ZCL_STATUS_REASON_PEER_SNAPSHOT_BUSY, 0) == false);
    ONP_CHECK("PEER_SNAPSHOT_BUSY does not page at 1 warning",
              node_status_reason_operator_needed(
                  ZCL_STATUS_REASON_PEER_SNAPSHOT_BUSY, 1) == false);
    ONP_CHECK("PEER_SNAPSHOT_BUSY does not page at 1000 warnings",
              node_status_reason_operator_needed(
                  ZCL_STATUS_REASON_PEER_SNAPSHOT_BUSY, 1000) == false);
    /* And it must NOT be the same verdict as the rung it exists to prevent
     * falling through to. If these ever agree, the guard is pointless. */
    ONP_CHECK("PEER_SNAPSHOT_BUSY and NO_PEERS disagree (the guard has a job)",
              node_status_reason_operator_needed(
                  ZCL_STATUS_REASON_PEER_SNAPSHOT_BUSY, 0) !=
              node_status_reason_operator_needed(
                  ZCL_STATUS_REASON_NO_PEERS, 0));
    return failures;
}

/* Exactly one reason's verdict may depend on warning_count. A second one
 * appearing means the question grew a second input behind everyone's back. */
static int case_only_one_reason_reads_warning_count(void)
{
    int failures = 0;
    int varying = 0;
    bool only_healthcheck = true;
    for (int i = 0; i < (int)ZCL_STATUS_REASON__COUNT; i++) {
        enum node_status_reason r = (enum node_status_reason)i;
        bool at_zero = node_status_reason_operator_needed(r, 0);
        bool at_three = node_status_reason_operator_needed(r, 3);
        if (at_zero == at_three)
            continue;
        varying++;
        if (r != ZCL_STATUS_REASON_HEALTHCHECK_UNHEALTHY) {
            printf("operator_needed_policy: reason '%s' varies with "
                   "warning_count\n", node_status_reason_name(r));
            only_healthcheck = false;
        }
    }
    ONP_CHECK("exactly one reason varies with warning_count", varying == 1);
    ONP_CHECK("the varying reason is HEALTHCHECK_UNHEALTHY", only_healthcheck);
    return failures;
}

/* An out-of-range reason is an unknown node state. Unknown must never read as
 * green: it pages, and it says so in the summary. A negative count must not
 * turn a warning-gated rung on either. */
static int case_out_of_range_fails_loud(void)
{
    int failures = 0;
    enum node_status_reason bogus =
        (enum node_status_reason)ZCL_STATUS_REASON__COUNT;
    ONP_CHECK("out-of-range reason pages the operator",
              node_status_reason_operator_needed(bogus, 0) == true);
    ONP_CHECK("out-of-range status is not 'healthy'",
              strcmp(node_status_reason_status(bogus), "healthy") != 0);
    ONP_CHECK("out-of-range summary is non-empty",
              node_status_reason_summary(bogus)[0] != '\0');
    ONP_CHECK("out-of-range name is non-empty",
              node_status_reason_name(bogus)[0] != '\0');
    ONP_CHECK("negative reason pages the operator",
              node_status_reason_operator_needed(
                  (enum node_status_reason)-1, 0) == true);
    ONP_CHECK("negative warning_count does not page HEALTHCHECK_UNHEALTHY",
              node_status_reason_operator_needed(
                  ZCL_STATUS_REASON_HEALTHCHECK_UNHEALTHY, -1) == false);
    return failures;
}

/* Only four status words are published to operators. A fifth one appearing
 * would break every dashboard and shell check that switches on them. */
static int case_status_vocabulary_is_closed(void)
{
    int failures = 0;
    bool closed = true;
    int healthy_rows = 0;
    for (int i = 0; i < (int)ZCL_STATUS_REASON__COUNT; i++) {
        enum node_status_reason r = (enum node_status_reason)i;
        const char *s = node_status_reason_status(r);
        bool ok = strcmp(s, "healthy") == 0 || strcmp(s, "catching_up") == 0 ||
                  strcmp(s, "degraded") == 0 || strcmp(s, "blocked") == 0;
        if (!ok) {
            printf("operator_needed_policy: reason '%s' has unknown status "
                   "'%s'\n", node_status_reason_name(r), s);
            closed = false;
        }
        if (strcmp(s, "healthy") == 0)
            healthy_rows++;
        if (node_status_reason_summary(r)[0] == '\0') {
            printf("operator_needed_policy: reason '%s' has an empty "
                   "summary\n", node_status_reason_name(r));
            closed = false;
        }
    }
    ONP_CHECK("every status is one of healthy/catching_up/degraded/blocked",
              closed);
    /* Exactly one reason may be "healthy", and it must be the no-problem one:
     * a second healthy row would let a real fault publish status=healthy. */
    ONP_CHECK("exactly one reason publishes status=healthy",
              healthy_rows == 1);
    ONP_CHECK("the healthy reason is NONE",
              strcmp(node_status_reason_status(ZCL_STATUS_REASON_NONE),
                     "healthy") == 0);
    /* Every "blocked" reason must page. A blocked node that does not ask for
     * an operator is the exact two-answers bug this consolidation removes. */
    bool blocked_all_page = true;
    for (int i = 0; i < (int)ZCL_STATUS_REASON__COUNT; i++) {
        enum node_status_reason r = (enum node_status_reason)i;
        if (strcmp(node_status_reason_status(r), "blocked") != 0)
            continue;
        if (!node_status_reason_operator_needed(r, 0)) {
            printf("operator_needed_policy: blocked reason '%s' does not "
                   "page\n", node_status_reason_name(r));
            blocked_all_page = false;
        }
    }
    ONP_CHECK("every status=blocked reason pages the operator",
              blocked_all_page);
    return failures;
}

int test_operator_needed_policy(void)
{
    int failures = 0;
    failures += case_table_is_complete();
    failures += case_truth_table();
    failures += case_peer_snapshot_busy_never_pages();
    failures += case_only_one_reason_reads_warning_count();
    failures += case_out_of_range_fails_loud();
    failures += case_status_vocabulary_is_closed();
    if (failures == 0)
        printf("test_operator_needed_policy: ALL PASSED\n");
    else
        printf("test_operator_needed_policy: %d FAILURE(S)\n", failures);
    return failures;
}
