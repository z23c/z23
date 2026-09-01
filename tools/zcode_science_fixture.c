/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcode_science_fixture — the acceptance-proof fixture tool for
 * tools/dev/science_acceptance.sh.
 *
 * WHY THIS TOOL EXISTS (glue, honestly named): the S3/S4 science leaves
 * admit study/result/reproduction/review/vote wires, but the CONTEXT
 * objects those wires bind (environment_policy.v1, benchmark_workload.v1,
 * task.v1, candidate.v1, benchmark_method.v1, science_findings.v1) have
 * NO command-leaf admission path — the landed tests seed them into the
 * workspace CAS with vcs_object_put_addressed (see
 * tests/harness/src/test_zcode_science_store.c and test_zcode_benchmark_exec.c,
 * whose fixtures this tool mirrors field-for-field). This tool does
 * exactly the same seeding through the SAME library codecs and the SAME
 * CAS write path, for two real node datadirs. It also:
 *   - v1mirror: re-wraps a committed benchmark_result.v2 observation as
 *     the benchmark_result.v1 wire the S4 reproduction executor requires
 *     (the executor refuses non-v1 originals by name; the S4 test
 *     hand-builds its v1 original the same way), preserving every bound
 *     root including the real evidence/sample roots;
 *   - seed-package / verify-package: admit a small content.v2 package to
 *     a node's package store via the real vcs_package_store_put_* APIs
 *     (the publish flow's own store writes), and re-verify a store's
 *     contents against a root after a swarm fetch.
 *
 * It NEVER speaks to the network and NEVER touches a running node's
 * node.db; it only reads/writes CAS and package-store files.
 *
 * Output contract: KEY=VALUE lines on stdout, exit 0 on success, exit 1
 * with a FATAL line on stderr on any failure.
 */

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/ed25519.h"
#include "support/cleanse.h"
#include "vcs/package_manifest.h"
#include "vcs/package_store.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_benchmark_receipt.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_science.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vcs/package_accept.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"

/* More tool-local shims: package_store.c also carries the release-
 * acceptance path (the publish flow's store entry point), which this tool
 * never calls — seed-package exercises only put_manifest/put_chunk, the
 * swarm's own store writes. The accept CONTEXT must still exist for
 * open/close, so it is a real allocation with no behavior; every function
 * that would classify a release aborts loudly (a call is a tool bug). */
struct vcs_package_accept *vcs_package_accept_new(void)
{
    return (struct vcs_package_accept *)zcl_calloc(1, 1, "fixture-accept-shim");
}
void vcs_package_accept_free(struct vcs_package_accept *accept)
{
    free(accept);
}
enum vcs_package_accept_result vcs_package_accept(
    struct vcs_package_accept *accept,
    const struct vcs_package_release *release)
{
    (void)accept;
    (void)release;
    abort();
}
const char *vcs_package_accept_result_string(
    enum vcs_package_accept_result result)
{
    (void)result;
    return "accept-path-unused-in-fixture-tool";
}
enum vcs_package_release_error vcs_package_release_id(
    const struct vcs_package_release *release,
    uint8_t out[VCS_PACKAGE_RELEASE_ID_BYTES])
{
    (void)release;
    (void)out;
    abort();
}
enum vcs_package_release_error vcs_package_release_serialize(
    const struct vcs_package_release *release, uint8_t **out,
    size_t *out_len)
{
    (void)release;
    (void)out;
    (void)out_len;
    abort();
}
enum vcs_package_recipe_error vcs_package_recipe_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_package_recipe *out)
{
    (void)wire;
    (void)wire_len;
    (void)out;
    abort();
}
enum vcs_package_recipe_error vcs_package_recipe_root(
    const struct vcs_package_recipe *recipe, uint8_t out[32])
{
    (void)recipe;
    (void)out;
    abort();
}
void vcs_package_recipe_free(struct vcs_package_recipe *recipe)
{
    (void)recipe;
    abort();
}

/* ed25519.c references the node RNG only from ed25519_new_key, which this
 * tool never calls (keys derive from fixed fixture seeds). Link shim. */
bool zcl_random_secret_bytes(uint8_t *buf, size_t n, const char *label)
{
    (void)buf;
    (void)n;
    (void)label;
    abort();
}

/* Tool-local shims for the node-global arg getters contexts/commons/modules/vcs references.
 * This tool is never a node: the store APIs it calls take an explicit
 * datadir and quota, so these exist only to satisfy the linker for the
 * global-store path it never uses (vcs_package_store_open_global). The
 * values mirror the defaults of a node booted without flags. */
bool GetBoolArg(const char *arg, bool default_val)
{
    (void)arg;
    return default_val;
}

int64_t GetArgInt(const char *arg, int64_t default_val)
{
    (void)arg;
    return default_val;
}

void GetDataDir(bool net_specific, char *out, size_t out_size)
{
    (void)net_specific;
    if (out && out_size)
        out[0] = '\0';
}

#define FIX_PAYLOAD_BYTES 2048u

static void fix_die(const char *what)
{
    fprintf(stderr, "zcode_science_fixture: FATAL: %s\n", what);
    exit(1);
}

/* Deterministic filler root: byte i = salt + base + i (the test fixtures'
 * zstore_root/zbex_root pattern, salted so two nodes get independent
 * studies). */
static void fix_root(uint8_t out[32], uint8_t salt, uint8_t base)
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(salt + base + (uint8_t)i);
}

static void fix_hex(const uint8_t in[32], char out[65])
{
    zcl_hex_encode(in, 32, out);
}

static bool fix_hex32(const char *hex, uint8_t out[32])
{
    return hex && strlen(hex) == 64 && zcl_hex_decode_lower(hex, out, 32);
}

static void fix_cas_put(const char *workspace, const uint8_t root[32],
                        const uint8_t *wire, size_t wire_len)
{
    if (!vcs_object_put_addressed(workspace, root, wire, wire_len))
        fix_die("vcs_object_put_addressed failed");
}

/* ── seed-context ───────────────────────────────────────────────────── */

static void fix_policy_open(struct vcs_zcode_environment_policy_v1 *policy)
{
    memset(policy, 0, sizeof(*policy));
    policy->schema_version = VCS_ZCODE_ENVIRONMENT_POLICY_VERSION;
}

static void fix_study(const uint8_t policy_root[32], uint8_t salt,
                      struct vcs_zcode_study_spec_v1 *study)
{
    memset(study, 0, sizeof(*study));
    study->schema_version = VCS_ZCODE_SCIENCE_VERSION;
    fix_root(study->hypothesis_root, salt, 1);
    fix_root(study->null_hypothesis_root, salt, 2);
    fix_root(study->source_root, salt, 3);
    fix_root(study->dependency_lock_root, salt, 4);
    fix_root(study->toolchain_capsule_root, salt, 5);
    fix_root(study->protocol_root, salt, 6);
    fix_root(study->workloads_root, salt, 7);
    fix_root(study->metrics_root, salt, 8);
    fix_root(study->estimator_tolerance_root, salt, 9);
    memcpy(study->environment_policy_root, policy_root, 32);
    fix_root(study->citations_root, salt, 11);
    fix_root(study->preregistration_policy_root, salt, 12);
    study->required_reproductions = 2;
    study->required_reviews = 3;
    study->sequence = 17;
    study->created_unix = 1000;
    study->expires_unix = 5000;
}

static void fix_task_candidate(const struct vcs_zcode_study_spec_v1 *study,
                               uint8_t salt,
                               struct vcs_zcode_task_v1 *task,
                               struct vcs_zcode_candidate_v1 *candidate,
                               uint8_t task_root[32],
                               uint8_t candidate_root[32])
{
    uint8_t study_root[32];
    if (vcs_zcode_study_spec_root(study, study_root) != VCS_ZCODE_SCIENCE_OK)
        fix_die("study root failed");
    memset(task, 0, sizeof(*task));
    task->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(task->source_root, study->source_root, 32);
    memcpy(task->dependency_lock_root, study->dependency_lock_root, 32);
    memcpy(task->toolchain_capsule_root, study->toolchain_capsule_root, 32);
    fix_root(task->write_scope_root, salt, 20);
    fix_root(task->acceptance_tests_root, salt, 21);
    fix_root(task->proof_policy_root, salt, 22);
    fix_root(task->model_policy_root, salt, 23);
    memcpy(task->goal_root, study_root, 32);
    task->capabilities = VCS_ZCODE_TASK_CAP_V1_MASK;
    task->max_changed_files = 32;
    task->max_patch_bytes = 1024 * 1024;
    task->max_context_bytes = 2 * 1024 * 1024;
    task->max_cpu_seconds = 120;
    task->max_memory_bytes = UINT64_C(512) * 1024 * 1024;
    task->max_output_bytes = UINT64_C(64) * 1024 * 1024;
    task->expires_unix = study->expires_unix;
    if (vcs_zcode_task_root(task, task_root) != VCS_ZCODE_DEV_OK)
        fix_die("task root failed");
    memset(candidate, 0, sizeof(*candidate));
    candidate->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(candidate->task_root, task_root, 32);
    memcpy(candidate->base_source_root, task->source_root, 32);
    fix_root(candidate->patch_root, salt, 24);
    fix_root(candidate->candidate_source_root, salt, 25);
    fix_root(candidate->adapter_policy_root, salt, 26);
    fix_root(candidate->author_pubkey, salt, 27);
    candidate->sequence = 1;
    candidate->created_unix = 1100;
    if (vcs_zcode_candidate_root(candidate, candidate_root) !=
        VCS_ZCODE_DEV_OK)
        fix_die("candidate root failed");
}

static void fix_method(const uint8_t workload_root[32], uint8_t salt,
                       struct vcs_zcode_benchmark_method_v1 *method)
{
    memset(method, 0, sizeof(*method));
    method->schema_version = VCS_ZCODE_BENCHMARK_METHOD_VERSION;
    memcpy(method->workload_root, workload_root, 32);
    fix_root(method->timer_root, salt, 0x42);
    fix_root(method->estimator_root, salt, 0x43);
    method->tolerance_ppm = 5000;
    method->warmup_samples = 2;
    method->measured_samples = 16;
    method->sample_distribution = VCS_ZCODE_SAMPLE_DIST_TRIMMED_MEAN;
    method->trim_percent = 10;
}

static int cmd_seed_context(const char *workspace, uint8_t salt)
{
    if (!vcs_object_store_init(workspace))
        fix_die("vcs_object_store_init failed (workspace must exist)");

    struct vcs_zcode_environment_policy_v1 policy;
    fix_policy_open(&policy);
    uint8_t policy_wire[VCS_ZCODE_ENVIRONMENT_POLICY_WIRE_BYTES];
    uint8_t policy_root[32];
    if (vcs_zcode_environment_policy_v1_serialize(&policy, policy_wire) !=
            VCS_ZCODE_RECEIPT_OK ||
        vcs_zcode_environment_policy_v1_root(&policy, policy_root) !=
            VCS_ZCODE_RECEIPT_OK)
        fix_die("policy wire failed");
    fix_cas_put(workspace, policy_root, policy_wire, sizeof(policy_wire));

    struct vcs_zcode_study_spec_v1 study;
    fix_study(policy_root, salt, &study);

    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    uint8_t task_root[32], candidate_root[32];
    fix_task_candidate(&study, salt, &task, &candidate, task_root,
                       candidate_root);

    uint8_t payload[FIX_PAYLOAD_BYTES];
    for (size_t i = 0; i < FIX_PAYLOAD_BYTES; i++)
        payload[i] = (uint8_t)(i * 7u + 3u + salt);
    uint8_t workload_wire[VCS_ZCODE_BENCHMARK_WORKLOAD_HEADER_BYTES +
                          FIX_PAYLOAD_BYTES];
    uint8_t workload_root[32];
    if (vcs_zcode_benchmark_workload_v1_serialize(
            payload, sizeof(payload), workload_wire,
            sizeof(workload_wire)) != VCS_ZCODE_RECEIPT_OK ||
        vcs_zcode_benchmark_workload_v1_root(workload_wire,
                                             sizeof(workload_wire),
                                             workload_root) !=
            VCS_ZCODE_RECEIPT_OK)
        fix_die("workload wire failed");
    fix_cas_put(workspace, workload_root, workload_wire,
                sizeof(workload_wire));

    struct vcs_zcode_benchmark_method_v1 method;
    fix_method(workload_root, salt, &method);

    uint8_t study_wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
    uint8_t study_root[32];
    uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
    uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    uint8_t method_wire[VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES];
    uint8_t method_root[32];
    if (vcs_zcode_study_spec_serialize(&study, study_wire) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_study_spec_root(&study, study_root) != VCS_ZCODE_SCIENCE_OK)
        fix_die("study wire failed");
    fix_cas_put(workspace, study_root, study_wire, sizeof(study_wire));
    if (vcs_zcode_task_serialize(&task, task_wire) != VCS_ZCODE_DEV_OK)
        fix_die("task wire failed");
    fix_cas_put(workspace, task_root, task_wire, sizeof(task_wire));
    if (vcs_zcode_candidate_serialize(&candidate, candidate_wire) !=
        VCS_ZCODE_DEV_OK)
        fix_die("candidate wire failed");
    fix_cas_put(workspace, candidate_root, candidate_wire,
                sizeof(candidate_wire));
    if (vcs_zcode_benchmark_method_serialize(&method, method_wire) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_benchmark_method_root(&method, method_root) !=
            VCS_ZCODE_SCIENCE_OK)
        fix_die("method wire failed");
    fix_cas_put(workspace, method_root, method_wire, sizeof(method_wire));

    char hex[65];
    fix_hex(policy_root, hex);
    printf("POLICY_ROOT=%s\n", hex);
    fix_hex(study_root, hex);
    printf("STUDY_ROOT=%s\n", hex);
    fix_hex(task_root, hex);
    printf("TASK_ROOT=%s\n", hex);
    fix_hex(candidate_root, hex);
    printf("CANDIDATE_ROOT=%s\n", hex);
    fix_hex(method_root, hex);
    printf("METHOD_ROOT=%s\n", hex);
    fix_hex(workload_root, hex);
    printf("WORKLOAD_ROOT=%s\n", hex);
    char *study_hex = zcl_malloc(sizeof(study_wire) * 2u + 1u, "fixture-study-wire-hex");
    if (!study_hex)
        fix_die("alloc study wire hex");
    zcl_hex_encode(study_wire, sizeof(study_wire), study_hex);
    printf("STUDY_WIRE=%s\n", study_hex);
    free(study_hex);
    return 0;
}

/* ── mkfindings ─────────────────────────────────────────────────────── */

static void fix_compose_findings(const char *study_hex, const char *task_hex,
                                 const char *candidate_hex,
                                 const char *result_hex, int64_t created_unix,
                                 uint8_t salt,
                                 struct vcs_zcode_science_findings_v1 *findings)
{
    memset(findings, 0, sizeof(*findings));
    findings->schema_version = VCS_ZCODE_SCIENCE_VERSION;
    if (!fix_hex32(study_hex, findings->study_root) ||
        !fix_hex32(task_hex, findings->task_root) ||
        !fix_hex32(candidate_hex, findings->candidate_root) ||
        !fix_hex32(result_hex, findings->result_root))
        fix_die("mkfindings: bad root hex");
    fix_root(findings->proof_set_root, salt, 41);
    fix_root(findings->methods_root, salt, 42);
    fix_root(findings->limitations_root, salt, 43);
    fix_root(findings->conflicts_root, salt, 44);
    findings->flags = 0;
    findings->severity = VCS_ZCODE_FINDING_MATERIAL;
    findings->sequence = 1;
    findings->created_unix = created_unix;
}

static int cmd_mkfindings(const char *workspace, const char *study_hex,
                          const char *task_hex, const char *candidate_hex,
                          const char *result_hex, int64_t created_unix,
                          uint8_t salt)
{
    struct vcs_zcode_science_findings_v1 findings;
    fix_compose_findings(study_hex, task_hex, candidate_hex, result_hex,
                         created_unix, salt, &findings);
    uint8_t wire[VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES];
    uint8_t root[32];
    if (vcs_zcode_science_findings_serialize(&findings, wire) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_science_findings_root(&findings, root) !=
            VCS_ZCODE_SCIENCE_OK)
        fix_die("findings wire failed");
    fix_cas_put(workspace, root, wire, sizeof(wire));
    char hex[65];
    fix_hex(root, hex);
    printf("FINDINGS_ROOT=%s\n", hex);
    return 0;
}

/* mkfindings-emit: compose the identical deterministic findings wire but do
 * NOT touch the CAS — print the wire so the caller admits it through the
 * zcode.science.findings.plan|commit leaves (the G4 command-leaf path the
 * acceptance proof exercises). */
static int cmd_mkfindings_emit(const char *study_hex, const char *task_hex,
                               const char *candidate_hex,
                               const char *result_hex, int64_t created_unix,
                               uint8_t salt)
{
    struct vcs_zcode_science_findings_v1 findings;
    fix_compose_findings(study_hex, task_hex, candidate_hex, result_hex,
                         created_unix, salt, &findings);
    uint8_t wire[VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES];
    uint8_t root[32];
    if (vcs_zcode_science_findings_serialize(&findings, wire) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_science_findings_root(&findings, root) !=
            VCS_ZCODE_SCIENCE_OK)
        fix_die("findings wire failed");
    char hex[65];
    fix_hex(root, hex);
    printf("FINDINGS_ROOT=%s\n", hex);
    printf("FINDINGS_WIRE_HEX=");
    for (size_t i = 0; i < sizeof(wire); i++)
        printf("%02x", wire[i]);
    printf("\n");
    return 0;
}

/* ── mkreview ───────────────────────────────────────────────────────── */

static int cmd_mkreview(const char *task_hex, const char *candidate_hex,
                        const char *findings_hex, int64_t created_unix,
                        uint64_t sequence, uint8_t salt)
{
    struct vcs_zcode_review_v1 review;
    memset(&review, 0, sizeof(review));
    review.schema_version = VCS_ZCODE_DEV_VERSION;
    if (!fix_hex32(task_hex, review.task_root) ||
        !fix_hex32(candidate_hex, review.candidate_root) ||
        !fix_hex32(findings_hex, review.findings_root))
        fix_die("mkreview: bad root hex");
    fix_root(review.proof_policy_root, salt, 22);
    fix_root(review.proof_set_root, salt, 41);
    fix_root(review.reviewer_pubkey, salt, 45);
    review.verdict = VCS_ZCODE_REVIEW_APPROVE;
    review.sequence = sequence;
    review.created_unix = created_unix;
    uint8_t wire[VCS_ZCODE_REVIEW_WIRE_BYTES];
    if (vcs_zcode_review_serialize(&review, wire) != VCS_ZCODE_DEV_OK)
        fix_die("review wire failed");
    char *hex = zcl_malloc(sizeof(wire) * 2u + 1u, "fixture-review-wire-hex");
    if (!hex)
        fix_die("alloc review wire hex");
    zcl_hex_encode(wire, sizeof(wire), hex);
    printf("REVIEW_WIRE=%s\n", hex);
    free(hex);
    return 0;
}

/* ── mkvote ─────────────────────────────────────────────────────────── */

static int cmd_mkvote(const char *property_hex, int64_t expires_unix,
                      uint8_t salt)
{
    uint8_t seed[32], secret[32], pubkey[32];
    fix_root(seed, salt, 53);
    ed25519_keypair(pubkey, secret, seed);
    struct vcs_zcode_curation_vote_v1 vote;
    memset(&vote, 0, sizeof(vote));
    vote.schema_version = VCS_ZCODE_SCIENCE_VERSION;
    fix_root(vote.network_genesis_root, salt, 50);
    fix_root(vote.voter_zid_root, salt, 51);
    if (!fix_hex32(property_hex, vote.property_root))
        fix_die("mkvote: bad property root");
    vote.signal = VCS_ZCODE_CURATION_USEFUL;
    vote.sequence = 1;
    vote.expires_unix = expires_unix;
    if (vcs_zcode_curation_vote_seal(&vote, secret, pubkey) !=
        VCS_ZCODE_SCIENCE_OK)
        fix_die("vote seal failed");
    uint8_t wire[VCS_ZCODE_CURATION_VOTE_WIRE_BYTES];
    uint8_t vote_id[32];
    if (vcs_zcode_curation_vote_serialize(&vote, wire) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_curation_vote_id(&vote, vote_id) != VCS_ZCODE_SCIENCE_OK)
        fix_die("vote wire failed");
    char *hex = zcl_malloc(sizeof(wire) * 2u + 1u, "fixture-vote-wire-hex");
    if (!hex)
        fix_die("alloc vote wire hex");
    zcl_hex_encode(wire, sizeof(wire), hex);
    printf("VOTE_WIRE=%s\n", hex);
    free(hex);
    char h[65];
    fix_hex(vote.network_genesis_root, h);
    printf("GENESIS_ROOT=%s\n", h);
    fix_hex(vote.voter_zid_root, h);
    printf("VOTER_ZID_ROOT=%s\n", h);
    fix_hex(pubkey, h);
    printf("SIGNER_PUBKEY=%s\n", h);
    fix_hex(vote_id, h);
    printf("VOTE_ID=%s\n", h);
    return 0;
}

/* ── v1mirror ───────────────────────────────────────────────────────── */

static int cmd_v1mirror(const char *workspace, const char *result_hex)
{
    uint8_t root[32];
    if (!fix_hex32(result_hex, root))
        fix_die("v1mirror: bad result root");
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0)
        fix_die("v1mirror: result not in CAS");
    struct vcs_zcode_benchmark_result_v2 v2;
    if (vcs_zcode_benchmark_result_v2_parse(wire, wire_len, &v2) !=
        VCS_ZCODE_SCIENCE_OK)
        fix_die("v1mirror: result is not a benchmark_result.v2");
    free(wire);
    struct vcs_zcode_benchmark_result_v1 v1;
    memset(&v1, 0, sizeof(v1));
    v1.schema_version = VCS_ZCODE_SCIENCE_VERSION;
    memcpy(v1.study_root, v2.study_root, 32);
    memcpy(v1.task_root, v2.task_root, 32);
    memcpy(v1.candidate_root, v2.candidate_root, 32);
    memcpy(v1.action_root, v2.action_root, 32);
    memcpy(v1.achieved_environment_root, v2.achieved_environment_root, 32);
    memcpy(v1.raw_sample_root, v2.raw_sample_root, 32);
    memcpy(v1.evidence_root, v2.evidence_root, 32);
    v1.status = v2.status;
    v1.challenge_block_height = v2.challenge_block_height;
    memcpy(v1.challenge_block_hash, v2.challenge_block_hash, 32);
    v1.sequence = v2.sequence;
    v1.started_unix = v2.started_unix;
    v1.finished_unix = v2.finished_unix;
    uint8_t v1_wire[VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES];
    uint8_t v1_root[32];
    if (vcs_zcode_benchmark_result_serialize(&v1, v1_wire) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_benchmark_result_root(&v1, v1_root) !=
            VCS_ZCODE_SCIENCE_OK)
        fix_die("v1mirror: v1 wire failed");
    fix_cas_put(workspace, v1_root, v1_wire, sizeof(v1_wire));
    char hex[65];
    fix_hex(v1_root, hex);
    printf("V1_ROOT=%s\n", hex);
    return 0;
}

/* ── cas-has ────────────────────────────────────────────────────────── */

static int cmd_cas_has(const char *workspace, const char *root_hex)
{
    uint8_t root[32];
    if (!fix_hex32(root_hex, root))
        fix_die("cas-has: bad root hex");
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    int rc = vcs_object_load_raw(workspace, root, &wire, &wire_len);
    free(wire);
    printf("PRESENT=%d\n", rc == 0 ? 1 : 0);
    return 0;
}

static int cmd_pubkey(const char *seed_hex)
{
    uint8_t seed[32], pubkey[32], secret[32];
    if (!fix_hex32(seed_hex, seed))
        fix_die("pubkey: bad seed hex");
    ed25519_keypair(pubkey, secret, seed);
    char hex[65];
    fix_hex(pubkey, hex);
    printf("PUBKEY=%s\n", hex);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(seed, sizeof(seed));
    return 0;
}

/* ── seed-package / verify-package ──────────────────────────────────── */

#define FIX_PKG_FILES 5u
#define FIX_PKG_FILE_MAX 512u

static const char *const k_pkg_paths[FIX_PKG_FILES] = {
    "LICENSE", "include/fix.h", "src/fix.c", "engine/entry/main.c", "tests/t1.c",
};

static int cmd_seed_package(const char *datadir, uint8_t salt)
{
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    uint8_t contents[FIX_PKG_FILES][FIX_PKG_FILE_MAX];
    size_t lens[FIX_PKG_FILES];
    for (size_t i = 0; i < FIX_PKG_FILES; i++) {
        size_t len = 120u + i * 61u + salt;
        for (size_t j = 0; j < len; j++)
            contents[i][j] = (uint8_t)(salt + i * 7u + j * 3u);
        lens[i] = len;
        uint8_t hash[32];
        if (!vcs_package_chunk_hash(contents[i], len, hash))
            fix_die("chunk hash failed");
        if (!vcs_package_manifest_add(&manifest, k_pkg_paths[i],
                                      VCS_PACKAGE_MODE_FILE, len, hash, 1))
            fix_die("manifest add failed");
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t root[32];
    if (!vcs_package_manifest_serialize(&manifest, &wire, &wire_len) ||
        !vcs_package_manifest_root(&manifest, root))
        fix_die("manifest serialize/root failed");

    struct vcs_package_store *store =
        vcs_package_store_open(datadir, vcs_package_store_quota_bytes());
    if (!store)
        fix_die("package store open failed");
    uint8_t stored_root[32];
    enum vcs_package_store_result r =
        vcs_package_store_put_manifest(store, wire, wire_len, stored_root);
    if (r != VCS_PACKAGE_STORE_OK ||
        memcmp(stored_root, root, 32) != 0)
        fix_die("store put_manifest failed");
    for (size_t i = 0; i < FIX_PKG_FILES; i++) {
        r = vcs_package_store_put_chunk(store, root, k_pkg_paths[i], 0,
                                        contents[i], lens[i]);
        if (r != VCS_PACKAGE_STORE_OK)
            fix_die("store put_chunk failed");
    }
    struct vcs_package_store_status st;
    memset(&st, 0, sizeof(st));
    if (!vcs_package_store_package_status(store, root, &st) || !st.complete)
        fix_die("seeded package not tracked-complete");
    vcs_package_store_close(store);
    vcs_package_manifest_free(&manifest);
    free(wire);
    char hex[65];
    fix_hex(root, hex);
    printf("PACKAGE_ROOT=%s\n", hex);
    printf("COMPLETE=1\n");
    return 0;
}

static int cmd_verify_package(const char *datadir, const char *root_hex)
{
    uint8_t root[32];
    if (!fix_hex32(root_hex, root))
        fix_die("verify-package: bad root hex");
    struct vcs_package_store *store =
        vcs_package_store_open(datadir, vcs_package_store_quota_bytes());
    if (!store)
        fix_die("package store open failed");
    struct vcs_package_store_status st;
    memset(&st, 0, sizeof(st));
    bool have_status = vcs_package_store_package_status(store, root, &st);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    enum vcs_package_store_result r =
        vcs_package_store_get_manifest_wire(store, root, &wire, &wire_len);
    if (r != VCS_PACKAGE_STORE_OK) {
        vcs_package_store_close(store);
        printf("COMPLETE=0\n");
        printf("ROOT_MATCH=0\n");
        printf("CHUNKS_OK=0\n");
        printf("CHUNKS_CHECKED=0\n");
        return 0;
    }
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    bool ok = vcs_package_manifest_parse(wire, wire_len, &manifest);
    uint8_t rederived[32];
    bool root_match = false;
    size_t chunks_checked = 0;
    bool chunks_ok = true;
    if (ok) {
        /* The stored wire re-parses; its canonical root must equal the
         * address it was fetched under. */
        root_match = vcs_package_manifest_root(&manifest, rederived) &&
                     memcmp(rederived, root, 32) == 0;
        for (size_t i = 0; i < manifest.count && chunks_ok; i++) {
            const struct vcs_package_file *f = &manifest.files[i];
            for (uint32_t c = 0; c < f->chunk_count && chunks_ok; c++) {
                uint8_t *chunk = NULL;
                size_t chunk_len = 0;
                r = vcs_package_store_get_chunk_at(store, root, i, c,
                                                   &chunk, &chunk_len);
                if (r != VCS_PACKAGE_STORE_OK) {
                    chunks_ok = false;
                    break;
                }
                uint8_t hash[32];
                bool h = vcs_package_chunk_hash(chunk, chunk_len, hash);
                chunks_ok = h &&
                    memcmp(hash, f->chunk_hashes + (size_t)c * 32u, 32) == 0;
                chunks_checked++;
                free(chunk);
            }
        }
    }
    vcs_package_manifest_free(&manifest);
    free(wire);
    vcs_package_store_close(store);
    printf("COMPLETE=%d\n",
           ok && have_status && st.tracked && st.complete ? 1 : 0);
    printf("ROOT_MATCH=%d\n", root_match ? 1 : 0);
    printf("CHUNKS_OK=%d\n", chunks_ok && chunks_checked > 0 ? 1 : 0);
    printf("CHUNKS_CHECKED=%zu\n", chunks_checked);
    return 0;
}

/* ── main ───────────────────────────────────────────────────────────── */

static int fix_usage(void)
{
    fprintf(stderr,
            "usage:\n"
            "  zcode_science_fixture seed-context <workspace> <salt>\n"
            "  zcode_science_fixture mkfindings <workspace> <study> <task>"
            " <candidate> <result> <created_unix> <salt>\n"
            "  zcode_science_fixture mkfindings-emit <study> <task>"
            " <candidate> <result> <created_unix> <salt>\n"
            "  zcode_science_fixture mkreview <task> <candidate> <findings>"
            " <created_unix> <sequence> <salt>\n"
            "  zcode_science_fixture mkvote <property_root> <expires_unix>"
            " <salt>\n"
            "  zcode_science_fixture v1mirror <workspace> <result_root>\n"
            "  zcode_science_fixture cas-has <workspace> <root>\n"
            "  zcode_science_fixture pubkey <seed>\n"
            "  zcode_science_fixture seed-package <datadir> <salt>\n"
            "  zcode_science_fixture verify-package <datadir> <root>\n");
    return 2;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return fix_usage();
    const char *cmd = argv[1];
    if (strcmp(cmd, "seed-context") == 0 && argc == 4)
        return cmd_seed_context(argv[2], (uint8_t)atoi(argv[3]));
    if (strcmp(cmd, "mkfindings") == 0 && argc == 9)
        return cmd_mkfindings(argv[2], argv[3], argv[4], argv[5], argv[6],
                              atoll(argv[7]), (uint8_t)atoi(argv[8]));
    if (strcmp(cmd, "mkfindings-emit") == 0 && argc == 8)
        return cmd_mkfindings_emit(argv[2], argv[3], argv[4], argv[5],
                                   atoll(argv[6]), (uint8_t)atoi(argv[7]));
    if (strcmp(cmd, "mkreview") == 0 && argc == 8)
        return cmd_mkreview(argv[2], argv[3], argv[4], atoll(argv[5]),
                            (uint64_t)strtoull(argv[6], NULL, 10),
                            (uint8_t)atoi(argv[7]));
    if (strcmp(cmd, "mkvote") == 0 && argc == 5)
        return cmd_mkvote(argv[2], atoll(argv[3]), (uint8_t)atoi(argv[4]));
    if (strcmp(cmd, "v1mirror") == 0 && argc == 4)
        return cmd_v1mirror(argv[2], argv[3]);
    if (strcmp(cmd, "cas-has") == 0 && argc == 4)
        return cmd_cas_has(argv[2], argv[3]);
    if (strcmp(cmd, "pubkey") == 0 && argc == 3)
        return cmd_pubkey(argv[2]);
    if (strcmp(cmd, "seed-package") == 0 && argc == 4)
        return cmd_seed_package(argv[2], (uint8_t)atoi(argv[3]));
    if (strcmp(cmd, "verify-package") == 0 && argc == 4)
        return cmd_verify_package(argv[2], argv[3]);
    return fix_usage();
}
