/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Proof tickets on the production worker path, for the build_fabric
 *          group. Real confined compiles run through the runtime's own attach
 *          and execute steps. A child process dies at each durable boundary
 *          of a live publication and worker start completes it; a restarted
 *          worker restores its issuer and receiver from CAS; a second worker
 *          shadows attach with the ticket decision, which counts HIT only
 *          for an independent approved signer. Attach stays the authority. */

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "test/test_core.h"

#include "base/hex.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "models/build_fabric.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "services/build_fabric_attach.h"
#include "services/build_fabric_proof_context.h"
#include "services/build_fabric_runtime.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_worker.h"
#include "vcs/build_action.h"
#include "vcs/package_store.h"
#include "vcs/proof_reuse.h"
#include "vcs/vcs_object.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include "util/spawn.h"
#include <sys/wait.h>
#include <unistd.h>

#define PW_CRASHED 42
#define PW_UNITS 3u
#define PW_STEP_LIMIT 32u

struct pw {
    struct node_db ndb;
    char dir[256];
    char path[320];
    char capsule_hex[65];
    unsigned serial;
};

struct pw_worker {
    uint8_t seed[32];
    uint8_t pubkey[32];
    uint8_t secret[32];
    char id[65];
    char signer_hex[65];
    struct build_fabric_proof_context *proof;
};

struct pw_tally {
    unsigned executed;
    unsigned reused;
    uint64_t executor_launches;
};

static void pw_worker_init(struct pw_worker *w, uint8_t fill)
{
    static const char domain[] = "zcl.build_worker.v1";
    memset(w, 0, sizeof(*w));
    memset(w->seed, fill, sizeof(w->seed));
    ed25519_keypair(w->pubkey, w->secret, w->seed);
    struct sha3_256_ctx sha;
    uint8_t digest[32];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, w->pubkey, 32);
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, 32, w->id);
    zcl_hex_encode(w->pubkey, 32, w->signer_hex);
}

static bool pw_open(struct pw *p, const char *tag)
{
    memset(p, 0, sizeof(*p));
    test_make_tmpdir(p->dir, sizeof(p->dir), "build_fabric_proof_wire", tag);
    (void)snprintf(p->path, sizeof(p->path), "%s/node.db", p->dir);
    struct vcs_toolchain_capsule_v1 capsule;
    uint8_t capsule_root[32];
    if (!node_db_open(&p->ndb, p->path) || !vcs_object_store_init(p->dir) ||
        !vcs_toolchain_capsule_v1_capture(&capsule) ||
        !vcs_toolchain_capsule_v1_root(&capsule, capsule_root))
        return false;
    zcl_hex_encode(capsule_root, 32, p->capsule_hex);
    return true;
}

static bool pw_reopen(struct pw *p)
{
    node_db_close(&p->ndb);
    memset(&p->ndb, 0, sizeof(p->ndb));
    return node_db_open(&p->ndb, p->path);
}

static bool pw_approve(struct pw *p, const struct pw_worker *w)
{
    struct db_build_worker row;
    memset(&row, 0, sizeof(row));
    memcpy(row.worker_id, w->id, sizeof(row.worker_id));
    memcpy(row.signer_pubkey, w->signer_hex, sizeof(row.signer_pubkey));
    (void)snprintf(row.capabilities, sizeof(row.capabilities),
                   "linux,x86-64-v3,gcc,%s", VCS_BUILD_ACTION_KIND_V1);
    int64_t now = (int64_t)platform_time_wall_unix();
    row.approved = 1;
    row.approved_at = now;
    row.last_seen_at = now;
    return build_fabric_worker_approve(&p->ndb, &row, now).ok;
}

/* One distinct compile unit's source bytes, stored at their own root. */
static bool pw_unit(struct pw *p, unsigned index, uint8_t input_root[32])
{
    char text[96];
    int n = snprintf(text, sizeof(text),
                     "int zbuild_wire_%u(void) { return %u; }\n", index,
                     index + 23u);
    if (n <= 0 || (size_t)n >= sizeof(text)) return false;
    sha3_256((const uint8_t *)text, (size_t)n, input_root);
    return vcs_object_put_addressed(p->dir, input_root,
                                    (const uint8_t *)text, (size_t)n);
}

static void pw_serial_hex(unsigned serial, uint8_t lane, char out[65])
{
    uint8_t raw[32];
    memset(raw, 0x5a, sizeof(raw));
    raw[0] = lane;
    raw[1] = (uint8_t)serial;
    raw[2] = (uint8_t)(serial >> 8);
    zcl_hex_encode(raw, 32, out);
}

/* Plan and submit one request; each call is fresh provenance over the same
 * executor inputs, so a later equal-input request is a genuine duplicate. */
static bool pw_request(struct pw *p, const uint8_t input_root[32])
{
    struct db_build_job job;
    struct db_build_action action;
    memset(&job, 0, sizeof(job));
    memset(&action, 0, sizeof(action));
    unsigned serial = ++p->serial;
    pw_serial_hex(serial, 1, job.source_sha256);
    pw_serial_hex(serial, 2, job.source_cas_sha3);
    memcpy(job.toolchain_sha3, p->capsule_hex, sizeof(job.toolchain_sha3));
    (void)snprintf(job.profile, sizeof(job.profile), "dev-x86-64-v3");
    (void)snprintf(job.state, sizeof(job.state), "PLANNED");
    job.created_at = job.updated_at = 100;
    (void)snprintf(action.kind, sizeof(action.kind), "%s",
                   VCS_BUILD_ACTION_KIND_V1);
    (void)snprintf(action.state, sizeof(action.state), "SNAPSHOTTED");
    zcl_hex_encode(input_root, 32, action.input_root_sha3);
    (void)snprintf(action.target, sizeof(action.target), "%s",
                   VCS_BUILD_TARGET_V1);
    uint8_t flags[32], environment[32];
    if (!vcs_build_action_v1_fixed_flags_root_for_kind(action.kind, flags) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(action.kind,
                                                             environment))
        return false;
    zcl_hex_encode(flags, 32, action.flags_sha3);
    zcl_hex_encode(environment, 32, action.environment_sha3);
    (void)snprintf(action.virtual_workdir, sizeof(action.virtual_workdir),
                   "%s", VCS_BUILD_VIRTUAL_ROOT_V1);
    (void)snprintf(action.declared_outputs, sizeof(action.declared_outputs),
                   "%s", VCS_BUILD_OUTPUT_V1);
    (void)snprintf(action.resource_policy, sizeof(action.resource_policy),
                   "%s", VCS_BUILD_RESOURCE_POLICY_V1);
    action.created_at = action.updated_at = 101;
    if (!build_fabric_action_id(&job, &action, action.action_id).ok ||
        !build_fabric_job_id(&job, action.action_id, job.job_id).ok)
        return false;
    memcpy(action.job_id, job.job_id, sizeof(action.job_id));
    int64_t now = (int64_t)platform_time_wall_unix();
    return build_fabric_plan(&p->ndb, &job, &action).ok &&
           build_fabric_submit(&p->ndb, job.job_id, now).ok;
}

static bool pw_proof_open(struct pw *p, struct pw_worker *w)
{
    struct zcl_result opened = build_fabric_proof_context_open(
        &p->ndb, p->dir, w->id, w->seed, &w->proof);
    if (!opened.ok) printf("(proof context: %s) ", opened.message);
    return opened.ok;
}

static void pw_proof_close(struct pw_worker *w)
{
    build_fabric_proof_context_close(w->proof);
    w->proof = NULL;
}

static bool pw_claim(struct pw *p, const struct pw_worker *w,
                     struct db_build_action *claimed, char lease[65],
                     bool *got)
{
    pw_serial_hex(++p->serial, 3, lease);
    return build_fabric_claim(&p->ndb, w->id, lease,
                              (int64_t)platform_time_wall_unix(), 300,
                              claimed, got).ok;
}

/* One iteration of the worker loop's work: the attach step, then on no HIT
 * a claim and the execute step. Returns false on a harness failure;
 * *idle when nothing was queued. */
static bool pw_loop_step(struct pw *p, struct pw_worker *w,
                         struct pw_tally *tally, bool *idle)
{
    *idle = false;
    struct db_build_receipt receipt;
    struct build_fabric_attach_report report;
    struct zcl_result attach = build_fabric_runtime_attach_step(
        &p->ndb, p->dir, w->secret, w->pubkey, w->proof, &receipt, &report);
    if (attach.ok && report.disposition == BUILD_FABRIC_ATTACH_HIT) {
        tally->reused++;
        return true;
    }
    struct db_build_action claimed;
    char lease[65];
    bool got = false;
    if (!pw_claim(p, w, &claimed, lease, &got)) return false;
    if (!got) {
        *idle = true;
        return true;
    }
    struct build_fabric_host_accounting accounting;
    struct zcl_result run = build_fabric_runtime_execute_step(
        &p->ndb, p->dir, p->dir, &claimed, lease, w->secret, w->pubkey,
        w->proof, &receipt, &accounting);
    if (!run.ok) {
        printf("(execute step: %s) ", run.message);
        return false;
    }
    tally->executed++;
    tally->executor_launches += accounting.host_executor_launches;
    return true;
}

static bool pw_drain(struct pw *p, struct pw_worker *w, struct pw_tally *t)
{
    memset(t, 0, sizeof(*t));
    for (unsigned step = 0; step < PW_STEP_LIMIT; step++) {
        bool idle = false;
        if (!pw_loop_step(p, w, t, &idle)) return false;
        if (idle) return true;
    }
    return false;
}

static struct build_fabric_proof_stats pw_stats(const struct pw_worker *w)
{
    struct build_fabric_proof_stats s;
    build_fabric_proof_context_stats(w->proof, &s);
    return s;
}

static int pw_pending(struct pw *p, const struct pw_worker *w)
{
    struct db_build_worker_proof_pending pending;
    return db_build_worker_proof_pending_find_checked(&p->ndb, w->id,
                                                      &pending);
}

static bool pw_head(struct pw *p, const struct pw_worker *w, char out[65])
{
    struct db_build_worker row;
    if (db_build_worker_find_checked(&p->ndb, w->id, &row) != 1) return false;
    memcpy(out, row.proof_checkpoint_head_sha3, 65);
    return true;
}

static void pw_print_stats(const char *label,
                           const struct build_fabric_proof_stats *s)
{
    printf("\n    %s: issuer=%s leaves=%llu receiver=%s tickets=%llu "
           "issued=%llu shadow=%llu unavailable=%llu ticket_hit=%llu "
           "ticket_hit_fail=%llu ticket_miss=%llu ticket_refuse=%llu "
           "attach_hit=%llu attach_miss=%llu attach_refused=%llu agree=%llu "
           "disagree=%llu (attach_only=%llu ticket_only=%llu) "
           "last=%s/%s\n    ", label, s->issuer_state,
           (unsigned long long)s->issuer_leaves, s->receiver_state,
           (unsigned long long)s->receiver_tickets,
           (unsigned long long)s->issued,
           (unsigned long long)s->shadow_decisions,
           (unsigned long long)s->shadow_unavailable,
           (unsigned long long)s->ticket_hit,
           (unsigned long long)s->ticket_hit_fail,
           (unsigned long long)s->ticket_miss,
           (unsigned long long)s->ticket_refuse,
           (unsigned long long)s->attach_hit,
           (unsigned long long)s->attach_miss,
           (unsigned long long)s->attach_refused,
           (unsigned long long)s->agree, (unsigned long long)s->disagree,
           (unsigned long long)s->disagree_attach_only,
           (unsigned long long)s->disagree_ticket_only,
           s->last_ticket_outcome, s->last_ticket_reason);
}

/* ── (a) A crash at each durable boundary of the live publication ──────── */

enum pw_crash_point {
    PW_AFTER_STAGE = BUILD_FABRIC_PROOF_ISSUE_AFTER_STAGE,
    PW_AFTER_TICKET = BUILD_FABRIC_PROOF_ISSUE_AFTER_TICKET_PUT,
    PW_AFTER_CHECKPOINT = BUILD_FABRIC_PROOF_ISSUE_AFTER_CHECKPOINT_PUT,
    PW_BEFORE_COMMIT = BUILD_FABRIC_PROOF_ISSUE_BEFORE_FINALIZE,
};

static const char *pw_crash_name(enum pw_crash_point point)
{
    switch (point) {
    case PW_AFTER_STAGE: return "after the pending stage";
    case PW_AFTER_TICKET: return "after the ticket CAS write";
    case PW_AFTER_CHECKPOINT: return "after the checkpoint CAS write";
    case PW_BEFORE_COMMIT: return "before the head commit";
    }
    return "unknown";
}

static void pw_die_at(enum build_fabric_proof_issue_point point,
                      void *context)
{
    if ((int)point == *(const int *)context) _exit(PW_CRASHED);
}

/* The production worker start and one real execution, in a child that dies
 * at `point` without closing anything. */
[[noreturn]] static void pw_crash_child(struct pw *p, struct pw_worker *w,
                                        int point)
{
    memset(&p->ndb, 0, sizeof(p->ndb));
    if (!node_db_open(&p->ndb, p->path)) _exit(2);
    if (!pw_proof_open(p, w)) _exit(3);
    build_fabric_proof_test_issue_hook(pw_die_at, &point);
    struct pw_tally tally = {0};
    bool idle = false;
    if (!pw_loop_step(p, w, &tally, &idle) || tally.executed != 1) _exit(4);
    _exit(5);
}

static bool pw_crash(struct pw *p, struct pw_worker *w,
                     enum pw_crash_point point)
{
    node_db_close(&p->ndb);
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) pw_crash_child(p, w, (int)point);
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return false;
    memset(&p->ndb, 0, sizeof(p->ndb));
    if (!WIFEXITED(status) || WEXITSTATUS(status) != PW_CRASHED) {
        printf("(child ended with status %d) ", status);
        return false;
    }
    return node_db_open(&p->ndb, p->path);
}

static int pw_case_crash(enum pw_crash_point point)
{
    int failures = 0;
    struct pw p;
    struct pw_worker a;
    pw_worker_init(&a, 41);
    printf("build_fabric proof wiring: crash %s, worker start completes... ",
           pw_crash_name(point));
    {
        ASSERT(pw_open(&p, "crash"));
        ASSERT(pw_approve(&p, &a));
        uint8_t input_root[32];
        ASSERT(pw_unit(&p, 1, input_root));
        ASSERT(pw_request(&p, input_root));
        ASSERT(pw_crash(&p, &a, point));
        /* The executed result stands; its ticket is staged, not published. */
        char head[65];
        ASSERT(pw_head(&p, &a, head));
        ASSERT_STR_EQ(head, "");
        ASSERT_EQ(pw_pending(&p, &a), 1);
        /* Worker start: recovery publishes exactly the staged ticket. */
        ASSERT(pw_proof_open(&p, &a));
        struct build_fabric_proof_stats s = pw_stats(&a);
        ASSERT_EQ(pw_pending(&p, &a), 0);
        ASSERT(pw_head(&p, &a, head));
        ASSERT(head[0] != '\0');
        ASSERT_STR_EQ(s.issuer_state, BUILD_FABRIC_PROOF_STATE_READY);
        ASSERT_STR_EQ(s.receiver_state, BUILD_FABRIC_PROOF_STATE_READY);
        ASSERT_EQ(s.issuer_leaves, 1u);
        ASSERT_EQ(s.receiver_tickets, 1u);
        ASSERT_EQ(s.issued, 0u);
        pw_proof_close(&a);
        /* A second restart rebuilds the same ticket from CAS alone. */
        ASSERT(pw_reopen(&p));
        ASSERT(pw_proof_open(&p, &a));
        s = pw_stats(&a);
        ASSERT_EQ(s.issuer_leaves, 1u);
        ASSERT_EQ(s.receiver_tickets, 1u);
        ASSERT_EQ(s.receiver_checkpoints, 1u);
        pw_proof_close(&a);
        node_db_close(&p.ndb);
        printf("OK\n");
    }
    if (0) {
_test_next:
        pw_proof_close(&a);
        node_db_close(&p.ndb);
    }
    return failures;
}

/* ── (b) Restart: N issued, N restored, N reused at the real launch point ─ */

static int pw_case_restart_rebuild(void)
{
    int failures = 0;
    struct pw p;
    struct pw_worker a;
    pw_worker_init(&a, 43);
    TEST("build_fabric proof wiring: restart restores N tickets; 0 executed, "
         "N reused") {
        ASSERT(pw_open(&p, "restart"));
        ASSERT(pw_approve(&p, &a));
        ASSERT(pw_proof_open(&p, &a));
        uint8_t roots[PW_UNITS][32];
        for (unsigned i = 0; i < PW_UNITS; i++) {
            ASSERT(pw_unit(&p, i + 10u, roots[i]));
            ASSERT(pw_request(&p, roots[i]));
        }
        struct pw_tally first;
        ASSERT(pw_drain(&p, &a, &first));
        ASSERT_EQ(first.executed, PW_UNITS);
        ASSERT_EQ(first.reused, 0u);
        ASSERT_EQ(first.executor_launches, (uint64_t)PW_UNITS);
        struct build_fabric_proof_stats s = pw_stats(&a);
        ASSERT_EQ(s.issued, (uint64_t)PW_UNITS);
        ASSERT_EQ(s.issue_refused, 0u);
        ASSERT_EQ(s.issuer_leaves, (uint64_t)PW_UNITS);
        ASSERT_EQ(s.receiver_tickets, (uint64_t)PW_UNITS);
        /* First requests: no donor, no ticket, both say run. */
        ASSERT_EQ(s.attach_miss, (uint64_t)PW_UNITS);
        ASSERT_EQ(s.ticket_miss, (uint64_t)PW_UNITS);
        ASSERT_EQ(s.agree, (uint64_t)PW_UNITS);
        ASSERT_STR_EQ(s.last_ticket_reason, VCS_PROOF_REUSE_WHY_NONE);
        pw_proof_close(&a);
        /* Restart: the process reopens its DB and starts the worker. */
        ASSERT(pw_reopen(&p));
        ASSERT(pw_proof_open(&p, &a));
        s = pw_stats(&a);
        ASSERT_STR_EQ(s.receiver_state, BUILD_FABRIC_PROOF_STATE_READY);
        ASSERT_EQ(s.receiver_tickets, (uint64_t)PW_UNITS);
        ASSERT_EQ(s.issuer_leaves, (uint64_t)PW_UNITS);
        ASSERT(vcs_proof_receiver_issuer_leaves(
                   build_fabric_proof_context_receiver(a.proof), a.pubkey) ==
               (uint64_t)PW_UNITS);
        for (unsigned i = 0; i < PW_UNITS; i++)
            ASSERT(pw_request(&p, roots[i]));
        uint64_t launches_before = zcl_spawn_thread_launch_count();
        struct pw_tally again;
        ASSERT(pw_drain(&p, &a, &again));
        uint64_t launches = zcl_spawn_thread_launch_count() - launches_before;
        ASSERT_EQ(again.executed, 0u);
        ASSERT_EQ(again.reused, PW_UNITS);
        ASSERT_EQ(again.executor_launches, 0u);
        /* Only attach's four closure probes per request; the shadow adds no
         * process. */
        ASSERT_EQ(launches, (uint64_t)(4u * PW_UNITS));
        s = pw_stats(&a);
        pw_print_stats("single-worker shadow", &s);
        /* D2: this worker's own tickets never count for its own requests. */
        ASSERT_EQ(s.attach_hit, (uint64_t)PW_UNITS);
        ASSERT_EQ(s.ticket_miss, (uint64_t)PW_UNITS);
        ASSERT_EQ(s.ticket_hit, 0u);
        ASSERT_STR_EQ(s.last_ticket_reason, VCS_PROOF_REUSE_WHY_INELIGIBLE);
        ASSERT_EQ(s.disagree_attach_only, (uint64_t)PW_UNITS);
        ASSERT_EQ(s.disagree_ticket_only, 0u);
        printf("work avoided: executed %u->%u reused %u executor_launches "
               "%llu->%llu host_launches=%llu ... ", first.executed,
               again.executed, again.reused,
               (unsigned long long)first.executor_launches,
               (unsigned long long)again.executor_launches,
               (unsigned long long)launches);
        pw_proof_close(&a);
        node_db_close(&p.ndb);
        PASS();
    }
    if (0) {
_test_next:
        pw_proof_close(&a);
        node_db_close(&p.ndb);
    }
    return failures;
}

/* ── (c) Two workers: HIT only for an independent approved signer ─────── */

/* A third approved worker signs and checkpoints a FAIL for the same key and
 * anchors it at its durable head, as its own worker start would. */
static bool pw_plant_fail(struct pw *p, const struct pw_worker *c,
                          const struct vcs_component_proof_key_v1 *key)
{
    struct vcs_proof_ticket_v1 t;
    memset(&t, 0, sizeof(t));
    t.verdict = VCS_PROOF_VERDICT_FAIL;
    t.basis = VCS_PROOF_BASIS_EXECUTED;
    t.action_class = VCS_PROOF_ACTION_BUILD;
    if (!vcs_component_proof_key_derive(key, t.input_key) ||
        !vcs_component_proof_key_preimage_root(key, t.key_preimage_root))
        return false;
    memcpy(t.source_root, key->roots[VCS_CPK_SOURCE_CLOSURE], 32);
    memset(t.evidence_root, 0x77, 32);
    t.checks_run = 1;
    t.checks_passed = 0;
    t.created_unix = (uint64_t)platform_time_wall_unix();
    uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
    uint8_t checkpoint[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    uint8_t root[32], head[32];
    char head_hex[65];
    struct vcs_proof_issuer_log *log = vcs_proof_issuer_log_new(c->seed);
    struct vcs_package_store *store =
        vcs_package_store_open(p->dir, vcs_package_store_quota_bytes());
    bool ok = log && store &&
              vcs_proof_issuer_log_append(log, &t, ticket) &&
              vcs_proof_issuer_log_checkpoint(log, t.created_unix,
                                              checkpoint) &&
              vcs_proof_ticket_store_put(store, ticket, sizeof(ticket),
                                         root) &&
              vcs_proof_ticket_store_put(store, checkpoint,
                                         sizeof(checkpoint), head);
    vcs_proof_issuer_log_free(log);
    vcs_package_store_close(store);
    if (!ok) return false;
    zcl_hex_encode(head, 32, head_hex);
    return db_build_worker_proof_head_cas(&p->ndb, c->id, c->signer_hex, "",
                                          head_hex);
}

/* One requester-side attach step; returns the disposition. */
static enum build_fabric_attach_disposition pw_attach(
    struct pw *p, struct pw_worker *w,
    struct build_fabric_attach_report *report)
{
    struct db_build_receipt receipt;
    (void)build_fabric_runtime_attach_step(&p->ndb, p->dir, w->secret,
                                           w->pubkey, w->proof, &receipt,
                                           report);
    return report->disposition;
}

static int pw_case_two_workers(void)
{
    int failures = 0;
    struct pw p;
    struct pw_worker a, b, c;
    pw_worker_init(&a, 51);
    pw_worker_init(&b, 53);
    pw_worker_init(&c, 57);
    TEST("build_fabric proof wiring: second worker shadows attach; HIT, "
         "quorum MISS, conflict REFUSE, known FAIL, revoked MISS") {
        ASSERT(pw_open(&p, "two"));
        ASSERT(pw_approve(&p, &a));
        ASSERT(pw_approve(&p, &b));
        ASSERT(pw_approve(&p, &c));
        uint8_t input_root[32];
        ASSERT(pw_unit(&p, 99, input_root));
        ASSERT(pw_request(&p, input_root));
        ASSERT(pw_proof_open(&p, &a));
        struct pw_tally tally;
        ASSERT(pw_drain(&p, &a, &tally));
        ASSERT_EQ(tally.executed, 1u);
        ASSERT_EQ(pw_stats(&a).issued, 1u);
        pw_proof_close(&a);
        /* Restart; B starts and requests the same inputs. */
        ASSERT(pw_reopen(&p));
        ASSERT(pw_proof_open(&p, &b));
        ASSERT_EQ(pw_stats(&b).receiver_tickets, 1u);
        ASSERT(pw_request(&p, input_root));
        struct build_fabric_attach_report report;
        ASSERT_EQ(pw_attach(&p, &b, &report), BUILD_FABRIC_ATTACH_HIT);
        ASSERT(report.proof_key_known);
        struct vcs_component_proof_key_v1 key = report.proof_key;
        struct build_fabric_proof_stats s = pw_stats(&b);
        ASSERT_EQ(s.ticket_hit, 1u);
        ASSERT_STR_EQ(s.last_ticket_outcome, "HIT");
        ASSERT_STR_EQ(s.last_ticket_reason, VCS_PROOF_REUSE_WHY_HIT);
        ASSERT_EQ(s.agree, 1u);
        /* Quorum 2 with one independent signer: MISS by name. */
        struct zcl_result quorum = build_fabric_proof_context_set_quorum(b.proof, 2);
        ASSERT_RESULT_OK(quorum);
        quorum = build_fabric_proof_context_set_quorum(b.proof, 0);
        ASSERT(!quorum.ok);
        ASSERT(pw_request(&p, input_root));
        ASSERT_EQ(pw_attach(&p, &b, &report), BUILD_FABRIC_ATTACH_HIT);
        s = pw_stats(&b);
        ASSERT_EQ(s.ticket_miss, 1u);
        ASSERT_STR_EQ(s.last_ticket_outcome, "MISS");
        ASSERT_STR_EQ(s.last_ticket_reason, VCS_PROOF_REUSE_WHY_QUORUM);
        ASSERT_EQ(s.disagree_attach_only, 1u);
        /* C's checkpointed FAIL for the same key: B restarts and refuses. */
        ASSERT(pw_plant_fail(&p, &c, &key));
        pw_proof_close(&b);
        ASSERT(pw_reopen(&p));
        ASSERT(pw_proof_open(&p, &b));
        ASSERT_EQ(pw_stats(&b).receiver_tickets, 2u);
        ASSERT(pw_request(&p, input_root));
        ASSERT_EQ(pw_attach(&p, &b, &report), BUILD_FABRIC_ATTACH_HIT);
        s = pw_stats(&b);
        ASSERT_EQ(s.ticket_refuse, 1u);
        ASSERT_STR_EQ(s.last_ticket_outcome, "REFUSE");
        ASSERT_STR_EQ(s.last_ticket_reason, "proof_observation_conflict");
        /* A revoked: attach stops using its result; C's FAIL is known. */
        int64_t now = (int64_t)platform_time_wall_unix();
        ASSERT(build_fabric_worker_revoke(&p.ndb, a.id, now).ok);
        ASSERT(pw_request(&p, input_root));
        ASSERT(pw_attach(&p, &b, &report) != BUILD_FABRIC_ATTACH_HIT);
        s = pw_stats(&b);
        ASSERT_EQ(s.ticket_hit_fail, 1u);
        ASSERT_STR_EQ(s.last_ticket_reason, VCS_PROOF_REUSE_WHY_KNOWN_FAIL);
        /* C revoked too: nothing eligible remains. */
        ASSERT(build_fabric_worker_revoke(&p.ndb, c.id, now).ok);
        ASSERT(pw_attach(&p, &b, &report) != BUILD_FABRIC_ATTACH_HIT);
        s = pw_stats(&b);
        ASSERT_EQ(s.ticket_miss, 1u);
        ASSERT_STR_EQ(s.last_ticket_reason, VCS_PROOF_REUSE_WHY_INELIGIBLE);
        pw_print_stats("two-worker shadow (B)", &s);
        /* Since B's restart: REFUSE beside HIT, then two agreeing non-HITs. */
        ASSERT_EQ(s.shadow_decisions, 3u);
        ASSERT_EQ(s.agree, 2u);
        ASSERT_EQ(s.disagree_attach_only, 1u);
        ASSERT_EQ(s.disagree, 1u);
        pw_proof_close(&b);
        node_db_close(&p.ndb);
        PASS();
    }
    if (0) {
_test_next:
        pw_proof_close(&a);
        pw_proof_close(&b);
        node_db_close(&p.ndb);
    }
    return failures;
}
/* ── (d) Issuance cost against the size of the issuer's history ──────── */

/* The worker's durable history as `rows` catalog rows: rows-1 signed tickets
 * and the checkpoint over them, anchored at the worker's durable head. The
 * fixture writes defer their fsync; the timed issuance does not. */
static bool pw_history_fill(struct pw *p, const struct pw_worker *w,
                            size_t rows)
{
    struct vcs_proof_issuer_log *log = vcs_proof_issuer_log_new(w->seed);
    struct vcs_package_store *store =
        vcs_package_store_open(p->dir, vcs_package_store_quota_bytes());
    uint64_t now = (uint64_t)platform_time_wall_unix();
    uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES];
    uint8_t checkpoint[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    uint8_t root[32], head[32];
    bool deferred = vcs_package_store_deferred_sync_enabled();
    vcs_package_store_set_deferred_sync(true);
    bool ok = log && store && rows >= 2;
    for (size_t i = 0; ok && i + 1 < rows; i++) {
        struct vcs_proof_ticket_v1 t;
        memset(&t, 0, sizeof(t));
        t.verdict = VCS_PROOF_VERDICT_PASS;
        t.basis = VCS_PROOF_BASIS_EXECUTED;
        t.action_class = VCS_PROOF_ACTION_BUILD;
        sha3_256((const uint8_t *)&i, sizeof(i), t.input_key);
        memcpy(t.key_preimage_root, t.input_key, 32);
        memcpy(t.source_root, t.input_key, 32);
        memset(t.artifact_root, 0x61, 32);
        memset(t.evidence_root, 0x62, 32);
        t.checks_run = t.checks_passed = 1;
        t.created_unix = now;
        ok = vcs_proof_issuer_log_append(log, &t, wire) &&
             vcs_proof_ticket_store_put(store, wire, sizeof(wire), root);
    }
    ok = ok && vcs_proof_issuer_log_checkpoint(log, now, checkpoint) &&
         vcs_proof_ticket_store_put(store, checkpoint, sizeof(checkpoint),
                                    head);
    vcs_package_store_set_deferred_sync(deferred);
    vcs_proof_issuer_log_free(log);
    vcs_package_store_close(store);
    if (!ok) return false;
    char head_hex[65];
    zcl_hex_encode(head, 32, head_hex);
    return db_build_worker_proof_head_cas(&p->ndb, w->id, w->signer_hex, "",
                                          head_hex);
}

/* One real compile with no proof context, then its issuance alone, timed. */
static bool pw_issue_timed(struct pw *p, struct pw_worker *w,
                           unsigned unit, int64_t *issue_us)
{
    uint8_t input_root[32];
    struct db_build_action claimed;
    struct db_build_receipt receipt;
    struct build_fabric_host_accounting accounting;
    char lease[65];
    bool got = false;
    if (!pw_unit(p, unit, input_root) || !pw_request(p, input_root) ||
        !pw_claim(p, w, &claimed, lease, &got) || !got ||
        !build_fabric_runtime_execute_step(&p->ndb, p->dir, p->dir, &claimed,
                                           lease, w->secret, w->pubkey, NULL,
                                           &receipt, &accounting).ok)
        return false;
    int64_t start = platform_time_monotonic_us();
    struct zcl_result issued = build_fabric_proof_issue_executed(
        w->proof, &p->ndb, p->dir, &claimed, &receipt, &accounting);
    *issue_us = platform_time_monotonic_us() - start;
    if (!issued.ok) printf("(issue: %s) ", issued.message);
    return issued.ok;
}

#define PW_COST_POINTS 3u
#define PW_COST_ISSUES 3u
/* Flat: the cheapest issuance at each larger history stays within this
 * factor of the cheapest at 100 rows, plus fixed slack for fsync jitter.
 * Replaying the history per issuance measured 22-33x from 100 to 1k rows. */
#define PW_COST_FACTOR 3
#define PW_COST_SLACK_US 250000

/* The 10k-row point spends about two minutes writing its fixture, so it runs
 * only on request: ZCL_PROOF_ISSUE_COST_10K=1. */
static unsigned pw_cost_points(void)
{
    const char *want = getenv("ZCL_PROOF_ISSUE_COST_10K");
    return want && strcmp(want, "1") == 0 ? PW_COST_POINTS
                                          : PW_COST_POINTS - 1u;
}

static int64_t pw_cost_min(const int64_t *cost, unsigned n)
{
    int64_t least = cost[0];
    for (unsigned i = 1; i < n; i++)
        if (cost[i] < least) least = cost[i];
    return least;
}

/* Worker start pays for history once; each issuance after it must not. */
static bool pw_cost_point(struct pw *p, struct pw_worker *w, size_t rows,
                          int64_t *least)
{
    if (!pw_open(p, "cost") || !pw_approve(p, w)) return false;
    int64_t t0 = platform_time_monotonic_us();
    if (!pw_history_fill(p, w, rows)) return false;
    int64_t t1 = platform_time_monotonic_us();
    if (!pw_proof_open(p, w)) return false;
    int64_t t2 = platform_time_monotonic_us();
    struct build_fabric_proof_stats s = pw_stats(w);
    if (s.issuer_leaves != (uint64_t)rows - 1u) return false;
    int64_t cost[PW_COST_ISSUES];
    for (unsigned i = 0; i < PW_COST_ISSUES; i++)
        if (!pw_issue_timed(p, w, 200u + i, &cost[i])) return false;
    s = pw_stats(w);
    *least = pw_cost_min(cost, PW_COST_ISSUES);
    printf("\n    proof_issue_cost rows=%zu fill_us=%lld start_us=%lld "
           "issue_us=%lld,%lld,%lld", rows, (long long)(t1 - t0),
           (long long)(t2 - t1), (long long)cost[0], (long long)cost[1],
           (long long)cost[2]);
    return s.issued == PW_COST_ISSUES && s.issue_refused == 0 &&
           s.issuer_leaves == (uint64_t)rows - 1u + PW_COST_ISSUES &&
           pw_pending(p, w) == 0;
}

static int pw_case_issue_cost(void)
{
    static const size_t rows[PW_COST_POINTS] = {100u, 1000u, 10000u};
    int failures = 0;
    struct pw p;
    struct pw_worker a;
    pw_worker_init(&a, 61);
    memset(&p, 0, sizeof(p));
    TEST("build_fabric proof wiring: issuance cost is flat in history") {
        unsigned points = pw_cost_points();
        int64_t least[PW_COST_POINTS];
        for (unsigned k = 0; k < points; k++) {
            ASSERT(pw_cost_point(&p, &a, rows[k], &least[k]));
            pw_proof_close(&a);
            node_db_close(&p.ndb);
        }
        printf("\n    ");
        for (unsigned k = 1; k < points; k++)
            ASSERT(least[k] <= PW_COST_FACTOR * least[0] + PW_COST_SLACK_US);
        PASS();
    }
    if (0) {
_test_next:
        pw_proof_close(&a);
        node_db_close(&p.ndb);
    }
    return failures;
}

/* ── (e) A failing proof state never changes attach or worker start ───── */

static bool pw_run_unit(struct pw *p, struct pw_worker *w, unsigned unit,
                        uint8_t root[32])
{
    struct pw_tally t;
    return pw_unit(p, unit, root) && pw_request(p, root) &&
           pw_drain(p, w, &t) && t.executed == 1u && t.reused == 0u;
}

/* A duplicate of `root` attaches once with this worker's proof state and
 * once with none: both must decide HIT and succeed alike. */
static bool pw_attach_unchanged(struct pw *p, struct pw_worker *w,
                                const uint8_t root[32])
{
    struct build_fabric_attach_report with, without;
    struct db_build_receipt receipt;
    if (!pw_request(p, root)) return false;
    struct zcl_result a = build_fabric_runtime_attach_step(
        &p->ndb, p->dir, w->secret, w->pubkey, w->proof, &receipt, &with);
    if (!pw_request(p, root)) return false;
    struct zcl_result b = build_fabric_runtime_attach_step(
        &p->ndb, p->dir, w->secret, w->pubkey, NULL, &receipt, &without);
    return a.ok && b.ok && with.disposition == BUILD_FABRIC_ATTACH_HIT &&
           without.disposition == with.disposition;
}

static const char *pw_fault_name(enum build_fabric_proof_fault fault)
{
    switch (fault) {
    case BUILD_FABRIC_PROOF_FAULT_ISSUE_STAGE: return "stage";
    case BUILD_FABRIC_PROOF_FAULT_ISSUE_TICKET_PUT: return "ticket put";
    case BUILD_FABRIC_PROOF_FAULT_ISSUE_FINALIZE: return "head finalize";
    default: return "other";
    }
}

/* A refused stage leaves nothing durable, so the issuer pauses until worker
 * start; a refusal after the stage keeps the row, and the next issuance
 * completes it before its own append. The compile, its admission, attach
 * and the next worker start are the same either way. */
static int pw_case_issue_fault(enum build_fabric_proof_fault fault)
{
    int failures = 0;
    struct pw p;
    struct pw_worker a;
    bool staged_kept = fault != BUILD_FABRIC_PROOF_FAULT_ISSUE_STAGE;
    pw_worker_init(&a, 67);
    memset(&p, 0, sizeof(p));
    printf("build_fabric proof wiring: refused %s leaves attach and worker "
           "start unchanged... ", pw_fault_name(fault));
    {
        ASSERT(pw_open(&p, "issue_fault"));
        ASSERT(pw_approve(&p, &a));
        ASSERT(pw_proof_open(&p, &a));
        uint8_t first[32], second[32];
        build_fabric_proof_test_fault(fault);
        bool ran = pw_run_unit(&p, &a, 300, first);
        build_fabric_proof_test_fault(BUILD_FABRIC_PROOF_FAULT_NONE);
        ASSERT(ran);
        struct build_fabric_proof_stats s = pw_stats(&a);
        ASSERT_EQ(s.issued, 0u);
        ASSERT_EQ(s.issue_refused, 1u);
        ASSERT_EQ(pw_pending(&p, &a), staged_kept ? 1 : 0);
        ASSERT_STR_EQ(s.issuer_state,
                      staged_kept ? BUILD_FABRIC_PROOF_STATE_READY
                                  : BUILD_FABRIC_PROOF_STATE_ISSUE_PAUSED);
        ASSERT(pw_attach_unchanged(&p, &a, first));
        /* The next compile runs; it publishes the kept row, then its own. */
        ASSERT(pw_run_unit(&p, &a, 301, second));
        s = pw_stats(&a);
        ASSERT_EQ(s.issued, staged_kept ? 1u : 0u);
        ASSERT_EQ(s.issuer_leaves, staged_kept ? 2u : 0u);
        ASSERT_EQ(pw_pending(&p, &a), 0);
        if (!staged_kept)
            ASSERT_STR_EQ(s.last_issue_refusal, "issuer_unavailable");
        /* Worker start: the durable history, nothing the fault lost. */
        pw_proof_close(&a);
        ASSERT(pw_reopen(&p));
        ASSERT(pw_proof_open(&p, &a));
        s = pw_stats(&a);
        ASSERT_STR_EQ(s.issuer_state, BUILD_FABRIC_PROOF_STATE_READY);
        ASSERT_EQ(s.issuer_leaves, staged_kept ? 2u : 0u);
        ASSERT_EQ(s.receiver_tickets, staged_kept ? 2u : 0u);
        ASSERT(pw_attach_unchanged(&p, &a, second));
        pw_proof_close(&a);
        node_db_close(&p.ndb);
        printf("OK\n");
    }
    if (0) {
_test_next:
        build_fabric_proof_test_fault(BUILD_FABRIC_PROOF_FAULT_NONE);
        pw_proof_close(&a);
        node_db_close(&p.ndb);
    }
    return failures;
}

/* Worker start with no context, a staged row recovery refuses, or no store:
 * the worker still starts, executes and attaches; only proof is closed. */
static int pw_case_open_fault(void)
{
    int failures = 0;
    struct pw p;
    struct pw_worker a;
    pw_worker_init(&a, 71);
    memset(&p, 0, sizeof(p));
    TEST("build_fabric proof wiring: a refused proof open never refuses the "
         "worker") {
        ASSERT(pw_open(&p, "open_fault"));
        ASSERT(pw_approve(&p, &a));
        uint8_t first[32], second[32], third[32];
        /* No context at all. */
        build_fabric_proof_test_fault(BUILD_FABRIC_PROOF_FAULT_OPEN_ALLOCATION);
        a.proof = build_fabric_runtime_proof_open(&p.ndb, p.dir, a.id, a.seed);
        build_fabric_proof_test_fault(BUILD_FABRIC_PROOF_FAULT_NONE);
        ASSERT(a.proof == NULL);
        ASSERT(pw_run_unit(&p, &a, 400, first));
        ASSERT(pw_attach_unchanged(&p, &a, first));
        /* A row staged by a refused publication, which recovery refuses. */
        ASSERT(pw_proof_open(&p, &a));
        build_fabric_proof_test_fault(BUILD_FABRIC_PROOF_FAULT_ISSUE_TICKET_PUT);
        bool ran = pw_run_unit(&p, &a, 401, second);
        build_fabric_proof_test_fault(BUILD_FABRIC_PROOF_FAULT_NONE);
        ASSERT(ran);
        ASSERT_EQ(pw_pending(&p, &a), 1);
        pw_proof_close(&a);
        build_fabric_proof_test_fault(BUILD_FABRIC_PROOF_FAULT_OPEN_RECOVERY);
        a.proof = build_fabric_runtime_proof_open(&p.ndb, p.dir, a.id, a.seed);
        build_fabric_proof_test_fault(BUILD_FABRIC_PROOF_FAULT_NONE);
        ASSERT(a.proof != NULL);
        struct build_fabric_proof_stats s = pw_stats(&a);
        ASSERT_STR_EQ(s.issuer_state,
                      BUILD_FABRIC_PROOF_STATE_PENDING_REFUSED);
        /* The head set is incomplete while a row is staged: named, closed. */
        ASSERT_STR_EQ(s.receiver_state,
                      BUILD_FABRIC_PROOF_STATE_HEADS_REFUSED);
        ASSERT_EQ(pw_pending(&p, &a), 1);
        ASSERT(pw_run_unit(&p, &a, 402, third));
        ASSERT(pw_attach_unchanged(&p, &a, second));
        s = pw_stats(&a);
        ASSERT_EQ(s.issued, 0u);
        ASSERT_STR_EQ(s.last_issue_refusal, "issuer_unavailable");
        ASSERT_EQ(pw_pending(&p, &a), 1);
        pw_proof_close(&a);
        /* No store: the datadir's zcode cannot exist beneath a file. */
        a.proof = build_fabric_runtime_proof_open(&p.ndb, p.path, a.id,
                                                  a.seed);
        ASSERT(a.proof != NULL);
        s = pw_stats(&a);
        ASSERT_STR_EQ(s.issuer_state,
                      BUILD_FABRIC_PROOF_STATE_STORE_UNAVAILABLE);
        ASSERT_STR_EQ(s.receiver_state,
                      BUILD_FABRIC_PROOF_STATE_STORE_UNAVAILABLE);
        ASSERT(pw_attach_unchanged(&p, &a, third));
        pw_proof_close(&a);
        /* The next worker start completes the kept row. */
        ASSERT(pw_proof_open(&p, &a));
        s = pw_stats(&a);
        ASSERT_STR_EQ(s.issuer_state, BUILD_FABRIC_PROOF_STATE_READY);
        ASSERT_EQ(s.issuer_leaves, 1u);
        ASSERT_EQ(pw_pending(&p, &a), 0);
        pw_proof_close(&a);
        node_db_close(&p.ndb);
        PASS();
    }
    if (0) {
_test_next:
        build_fabric_proof_test_fault(BUILD_FABRIC_PROOF_FAULT_NONE);
        pw_proof_close(&a);
        node_db_close(&p.ndb);
    }
    return failures;
}

/* A shadow that cannot decide counts itself unavailable; attach decides and
 * succeeds exactly as it does with no proof state. */
static int pw_case_shadow_fault(void)
{
    int failures = 0;
    struct pw p;
    struct pw_worker a;
    pw_worker_init(&a, 73);
    memset(&p, 0, sizeof(p));
    TEST("build_fabric proof wiring: a failed shadow never changes attach") {
        ASSERT(pw_open(&p, "shadow_fault"));
        ASSERT(pw_approve(&p, &a));
        ASSERT(pw_proof_open(&p, &a));
        uint8_t root[32];
        ASSERT(pw_run_unit(&p, &a, 500, root));
        uint64_t unavailable = pw_stats(&a).shadow_unavailable;
        build_fabric_proof_test_fault(BUILD_FABRIC_PROOF_FAULT_SHADOW_DECIDE);
        bool same = pw_attach_unchanged(&p, &a, root);
        build_fabric_proof_test_fault(BUILD_FABRIC_PROOF_FAULT_NONE);
        ASSERT(same);
        struct build_fabric_proof_stats s = pw_stats(&a);
        ASSERT_EQ(s.shadow_unavailable, unavailable + 1u);
        ASSERT_STR_EQ(s.last_ticket_outcome, "unavailable");
        ASSERT_STR_EQ(s.last_ticket_reason, "trust_unreadable");
        ASSERT_EQ(s.attach_hit, 1u);
        pw_proof_close(&a);
        node_db_close(&p.ndb);
        PASS();
    }
    if (0) {
_test_next:
        build_fabric_proof_test_fault(BUILD_FABRIC_PROOF_FAULT_NONE);
        pw_proof_close(&a);
        node_db_close(&p.ndb);
    }
    return failures;
}
#endif

#include "test_group_catalog.h"

int bf_proof_wiring_cases(void);
int bf_proof_wiring_shard(unsigned shard);
bool bf_proof_wiring_partition_valid(void);

#if defined(__linux__)
static int pw_stage(void) { return pw_case_crash(PW_AFTER_STAGE); }
static int pw_ticket(void) { return pw_case_crash(PW_AFTER_TICKET); }
static int pw_checkpoint(void) { return pw_case_crash(PW_AFTER_CHECKPOINT); }
static int pw_commit(void) { return pw_case_crash(PW_BEFORE_COMMIT); }
static int pw_fault_stage(void) { return pw_case_issue_fault(BUILD_FABRIC_PROOF_FAULT_ISSUE_STAGE); }
static int pw_fault_ticket(void) { return pw_case_issue_fault(BUILD_FABRIC_PROOF_FAULT_ISSUE_TICKET_PUT); }
static int pw_fault_finalize(void) { return pw_case_issue_fault(BUILD_FABRIC_PROOF_FAULT_ISSUE_FINALIZE); }
struct pw_row { const char *name; int (*run)(void); unsigned owner; };
#define PW_ROW(fn, shard) { #fn, fn, shard }
static const struct pw_row pw_rows[] = {
    PW_ROW(pw_stage, 1), PW_ROW(pw_ticket, 1), PW_ROW(pw_checkpoint, 1),
    PW_ROW(pw_commit, 1), PW_ROW(pw_case_restart_rebuild, 1),
    PW_ROW(pw_case_two_workers, 2), PW_ROW(pw_case_issue_cost, 2),
    PW_ROW(pw_fault_stage, 3), PW_ROW(pw_fault_ticket, 3),
    PW_ROW(pw_fault_finalize, 3), PW_ROW(pw_case_open_fault, 3),
    PW_ROW(pw_case_shadow_fault, 3),
};
#undef PW_ROW
static const char *const pw_original[] = {
    "pw_stage", "pw_ticket", "pw_checkpoint", "pw_commit",
    "pw_case_restart_rebuild", "pw_case_two_workers", "pw_case_issue_cost",
    "pw_fault_stage", "pw_fault_ticket", "pw_fault_finalize",
    "pw_case_open_fault", "pw_case_shadow_fault"
};
static size_t pw_owners(const char *name)
{
    size_t n = 0;
    for (size_t i = 0; i < sizeof(pw_rows) / sizeof(pw_rows[0]); i++)
        if (strcmp(name, pw_rows[i].name) == 0) n++;
    return n;
}
static bool pw_partition_valid(void)
{
    unsigned counts[4] = {0};
    if (sizeof(pw_rows) / sizeof(pw_rows[0]) != sizeof(pw_original) / sizeof(pw_original[0])) return false;
    for (size_t i = 0; i < sizeof(pw_rows) / sizeof(pw_rows[0]); i++) {
        if (pw_rows[i].owner < 1 || pw_rows[i].owner > 3 || !pw_rows[i].run) return false;
        counts[pw_rows[i].owner]++;
    }
    for (size_t i = 0; i < sizeof(pw_original) / sizeof(pw_original[0]); i++)
        if (pw_owners(pw_original[i]) != 1) return false;
    return counts[1] && counts[2] && counts[3];
}
#endif
static bool pw_registry_valid(void)
{
    const char *umbrella = "test_build_fabric";
    if (!zcl_test_group_is_umbrella(umbrella) || zcl_test_group_umbrella_shard_count(umbrella) != 4) return false;
    for (unsigned i = 1; i <= 4; i++) {
        char id[ZCL_TEST_GROUP_FULL_MAX];
        (void)snprintf(id, sizeof(id), "test_build_fabric_shard_%02u", i);
        if (!zcl_test_group_is_umbrella_shard(umbrella, id)) return false;
    }
    return true;
}
bool bf_proof_wiring_partition_valid(void)
{
#if defined(__linux__)
    return pw_registry_valid() && pw_partition_valid();
#else
    return pw_registry_valid();
#endif
}
int bf_proof_wiring_shard(unsigned shard)
{
    if (shard > 3 || !bf_proof_wiring_partition_valid()) return 1;
#if defined(__linux__)
    int failures = 0;
    for (size_t i = 0; i < sizeof(pw_rows) / sizeof(pw_rows[0]); i++)
        if (!shard || pw_rows[i].owner == shard) failures += pw_rows[i].run();
    return failures;
#else
    return 0;
#endif
}
int bf_proof_wiring_cases(void) { return bf_proof_wiring_shard(0); }
