/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_discovery_projection — the S5 adapter slice of the ZCODE
 * Scientific Metaverse: the rebuildable discovery-graph projection over
 * the S3 science index/CAS, feeding the owned S5 pure rank core.
 *
 * Proofs:
 *   1. Rebuild determinism + input-order invariance: the same objects
 *      admitted in different orders (two workspaces, reverse insertion)
 *      yield byte-identical corpus/graph/seed-set roots, render order, and
 *      convergence residual; a drop-and-rebuild from the same CAS repeats
 *      them.
 *   2. Version/fork collapse: candidates linked through base_source_root
 *      (the zcode_dev lineage recording) collapse two versions and two
 *      forks of one lineage into ONE node; same-source studies collapse.
 *   3. Omission bound: 4097 properties admit exactly 4096 deterministically
 *      (by root ascending) with the omitted count recorded.
 *   4. Citation-spam cap: a node citing more than 64 distinct properties
 *      keeps exactly 64 (cited root ascending), the rest omitted + counted.
 *   5. Vote aggregation: only signature-valid, non-expired, in-network,
 *      positive-signal, non-replay votes become seed weight; one vote per
 *      voter per lineage.
 *   6. Mechanical firewall: a rank projection that flags a valid result
 *      (FLAG-only votes, zero seed weight) changes nothing on the
 *      zcode_science_service work.plan/commit admission path, and the
 *      projection itself writes nothing.
 *   7. Command smoke: zcode.science.discover renders explanations and
 *      honors filter-first; zcode.science.rank.snapshot returns roots +
 *      counts without entries.
 *
 * Services run in-process on ./test-tmp workspaces and node.db files; the
 * canonical wires are built with the S1 codecs (test_zcode_science_store.c
 * fixture patterns). */

#include "test/test_core.h"

#include "base/hex.h"
#include "command/native_command.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "services/zcode_science_service.h"
#include "util/safe_alloc.h"
#include "vcs/build_action.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_discovery_projection.h"
#include "vcs/zcode_discovery_rank.h"
#include "vcs/zcode_science.h"
#include "vcs/zcode_science_index.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZPROJ_DIR_CAP 512
#define ZPROJ_NOW 2000

static int g_zproj_seq;

static void zproj_root(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

static int zproj_root_cmp(const void *a, const void *b)
{
    return memcmp(a, b, 32);
}

static bool zproj_setup(char *dir, size_t cap)
{
    int n = snprintf(dir, cap, "test-tmp/zcode_discovery_projection_%d_%d",
                     (int)getpid(), g_zproj_seq++);
    if (n <= 0 || (size_t)n >= cap)
        return false;
    char cmd[ZPROJ_DIR_CAP * 2 + 32];
    n = snprintf(cmd, sizeof(cmd), "rm -rf '%s' && mkdir -p '%s'", dir, dir);
    if (n <= 0 || (size_t)n >= sizeof(cmd) || system(cmd) != 0)
        return false;
    return vcs_object_store_init(dir);
}

static bool zproj_setup_db(struct node_db *ndb, char *dir, size_t cap)
{
    if (!zproj_setup(dir, cap))
        return false;
    char db[ZPROJ_DIR_CAP + 16];
    int n = snprintf(db, sizeof(db), "%s/node.db", dir);
    return n > 0 && (size_t)n < sizeof(db) && node_db_open(ndb, db);
}

static void zproj_teardown(const char *dir)
{
    char cmd[ZPROJ_DIR_CAP + 16];
    int n = snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (n > 0 && (size_t)n < sizeof(cmd))
        (void)system(cmd);
}

static int zproj_cas_object_count(const char *workspace)
{
    char objects[ZPROJ_DIR_CAP + 24];
    int n = snprintf(objects, sizeof(objects), "%s/.zvcs/objects", workspace);
    if (n <= 0 || (size_t)n >= sizeof(objects))
        return -1;
    DIR *d = opendir(objects);
    if (!d)
        return 0;
    int count = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strlen(de->d_name) != 2)
            continue;
        char shard[ZPROJ_DIR_CAP + 32];
        n = snprintf(shard, sizeof(shard), "%s/%s", objects, de->d_name);
        if (n <= 0 || (size_t)n >= sizeof(shard))
            continue;
        DIR *sd = opendir(shard);
        if (!sd)
            continue;
        struct dirent *se;
        while ((se = readdir(sd)) != NULL)
            if (strlen(se->d_name) == 62)
                count++;
        closedir(sd);
    }
    closedir(d);
    return count;
}

/* ── fixtures ────────────────────────────────────────────────────── */

/* A structurally valid study; field roots are memset(base) with byte 1
 * distinguishing the field, so studies never share a filler root.
 * citations_root starts as a filler that names no CAS object (no citation
 * edges) until the caller commits a real citation set. */
static void zproj_study(struct vcs_zcode_study_spec_v1 *study, uint8_t base,
                        uint8_t source_byte, uint64_t sequence)
{
    memset(study, 0, sizeof(*study));
    study->schema_version = VCS_ZCODE_SCIENCE_VERSION;
    uint8_t *fields[] = {
        study->hypothesis_root, study->null_hypothesis_root,
        study->dependency_lock_root, study->toolchain_capsule_root,
        study->protocol_root, study->workloads_root, study->metrics_root,
        study->estimator_tolerance_root, study->environment_policy_root,
        study->citations_root, study->preregistration_policy_root,
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        zproj_root(fields[i], base);
        fields[i][1] = (uint8_t)(i + 1u);
    }
    zproj_root(study->source_root, source_byte);
    study->required_reproductions = 2;
    study->required_reviews = 3;
    study->sequence = sequence;
    study->created_unix = 1000;
    study->expires_unix = 5000;
}

static bool zproj_put(const char *workspace, const uint8_t root[32],
                      const uint8_t *wire, size_t wire_len)
{
    return vcs_object_put_addressed(workspace, root, wire, wire_len);
}

static bool zproj_put_study(const char *workspace,
                            struct vcs_zcode_study_spec_v1 *study,
                            uint8_t root_out[32])
{
    uint8_t wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
    return vcs_zcode_study_spec_serialize(study, wire) ==
               VCS_ZCODE_SCIENCE_OK &&
           vcs_zcode_study_spec_root(study, root_out) ==
               VCS_ZCODE_SCIENCE_OK &&
           zproj_put(workspace, root_out, wire, sizeof(wire));
}

/* Commit a citation set for one study: encodes the canonical object,
 * stores it addressed by its commitment, points the study's citations_root
 * at it, and re-stores the study wire. */
static bool zproj_commit_citations(const char *workspace,
                                   struct vcs_zcode_study_spec_v1 *study,
                                   const uint8_t *cited, size_t cited_count,
                                   uint8_t study_root_out[32])
{
    uint8_t payload[VCS_ZCODE_DISCOVERY_PROJECTION_MAX_CITATION_SET * 32u];
    size_t count = 0;
    if (!vcs_zcode_discovery_citation_set_encode(cited, cited_count, payload,
                                                 &count,
                                                 study->citations_root))
        return false;
    return zproj_put(workspace, study->citations_root, payload,
                     count * 32u) &&
           zproj_put_study(workspace, study, study_root_out);
}

static void zproj_candidate(struct vcs_zcode_candidate_v1 *candidate,
                            uint8_t filler, const uint8_t base_source[32],
                            const uint8_t candidate_source[32])
{
    memset(candidate, 0, sizeof(*candidate));
    candidate->schema_version = VCS_ZCODE_DEV_VERSION;
    zproj_root(candidate->task_root, (uint8_t)(filler + 1u));
    memcpy(candidate->base_source_root, base_source, 32);
    zproj_root(candidate->patch_root, (uint8_t)(filler + 2u));
    memcpy(candidate->candidate_source_root, candidate_source, 32);
    zproj_root(candidate->adapter_policy_root, (uint8_t)(filler + 3u));
    zproj_root(candidate->author_pubkey, (uint8_t)(filler + 4u));
    candidate->sequence = 1;
    candidate->created_unix = 1100;
}

static bool zproj_put_candidate(const char *workspace,
                                struct vcs_zcode_candidate_v1 *candidate,
                                uint8_t root_out[32])
{
    uint8_t wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    return vcs_zcode_candidate_serialize(candidate, wire) ==
               VCS_ZCODE_DEV_OK &&
           vcs_zcode_candidate_root(candidate, root_out) == VCS_ZCODE_DEV_OK &&
           zproj_put(workspace, root_out, wire, sizeof(wire));
}

/* A structurally valid benchmark_result.v2 pinned to a study and candidate
 * (method/profile roots are computed from real objects, mirroring the S3
 * store fixtures). */
static bool zproj_put_result(const char *workspace,
                             const struct vcs_zcode_study_spec_v1 *study,
                             const uint8_t candidate_root[32],
                             uint8_t status, uint64_t sequence,
                             uint8_t root_out[32])
{
    struct vcs_zcode_benchmark_method_v1 method;
    struct vcs_zcode_hardware_profile_v1 profile;
    struct vcs_build_action_v1 action;
    struct vcs_zcode_benchmark_result_v2 result;
    memset(&method, 0, sizeof(method));
    method.schema_version = VCS_ZCODE_BENCHMARK_METHOD_VERSION;
    zproj_root(method.workload_root, 0x41);
    zproj_root(method.timer_root, 0x42);
    zproj_root(method.estimator_root, 0x43);
    method.tolerance_ppm = 5000;
    method.warmup_samples = 10;
    method.measured_samples = 1000;
    method.sample_distribution = VCS_ZCODE_SAMPLE_DIST_TRIMMED_MEAN;
    method.trim_percent = 10;
    memset(&profile, 0, sizeof(profile));
    profile.schema_version = VCS_ZCODE_HARDWARE_PROFILE_VERSION;
    memcpy(profile.cpu_vendor, "GenuineIntel", 12);
    profile.physical_cores = 8;
    profile.logical_cores = 16;
    profile.ram_mib = 32768;
    profile.isa_bits = VCS_ZCODE_HW_ISA_AVX2;
    memcpy(profile.os_sysname, "Linux", 5);
    memcpy(profile.os_machine, "x86_64", 6);
    memcpy(profile.os_release, "6.9.0-test", 10);
    profile.tsc_freq_hz = UINT64_C(3000000000);
    memcpy(profile.timer_source, "tsc", 3);
    profile.captured_unix = 1000;
    memset(&action, 0, sizeof(action));
    zproj_root(action.source_sha256, 60);
    zproj_root(action.source_cas_sha3, 61);
    zproj_root(action.input_root_sha3, 62);
    zproj_root(action.toolchain_capsule_sha3, 63);
    if (!vcs_build_action_v1_fixed_flags_root_for_kind(
            VCS_BUILD_ACTION_KIND_BENCHMARK_V1, action.flags_sha3) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            VCS_BUILD_ACTION_KIND_BENCHMARK_V1, action.environment_sha3))
        return false;
    {
        /* The kind's fixed descriptors: root_for_kind rejects an action
         * whose text fields do not match them exactly (and empty text is
         * never valid). */
        const char *workdir = NULL, *output = NULL, *policy = NULL;
        if (!vcs_build_action_v1_descriptors(
                VCS_BUILD_ACTION_KIND_BENCHMARK_V1, &workdir, &output,
                &policy))
            return false;
        (void)snprintf(action.target, sizeof(action.target), "%s",
                       VCS_BUILD_TARGET_V1);
        (void)snprintf(action.profile, sizeof(action.profile), "science");
        (void)snprintf(action.virtual_workdir,
                       sizeof(action.virtual_workdir), "%s", workdir);
        (void)snprintf(action.declared_outputs,
                       sizeof(action.declared_outputs), "%s", output);
        (void)snprintf(action.resource_policy,
                       sizeof(action.resource_policy), "%s", policy);
        action.sequence = 1;
    }
    memset(&result, 0, sizeof(result));
    result.schema_version = VCS_ZCODE_BENCHMARK_RESULT_V2_VERSION;
    if (vcs_zcode_study_spec_root(study, result.study_root) !=
        VCS_ZCODE_SCIENCE_OK)
        return false;
    zproj_root(result.task_root, (uint8_t)(0x30 + sequence));
    memcpy(result.candidate_root, candidate_root, 32);
    if (vcs_build_action_v1_root_for_kind(
            VCS_BUILD_ACTION_KIND_BENCHMARK_V1, &action,
            result.action_root) == 0)
        return false;
    zproj_root(result.achieved_environment_root, 31);
    zproj_root(result.raw_sample_root, 32);
    zproj_root(result.evidence_root, (uint8_t)(33 + sequence));
    result.status = status;
    result.challenge_block_height = 3200000;
    zproj_root(result.challenge_block_hash, 34);
    result.sequence = sequence;
    result.started_unix = 1200;
    result.finished_unix = 1300;
    if (vcs_zcode_benchmark_method_root(&method, result.method_root) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_hardware_profile_root(&profile,
                                        result.hardware_profile_root) !=
            VCS_ZCODE_SCIENCE_OK)
        return false;
    uint8_t wire[VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES];
    return vcs_zcode_benchmark_result_v2_serialize(&result, wire) ==
               VCS_ZCODE_SCIENCE_OK &&
           vcs_zcode_benchmark_result_v2_root(&result, root_out) ==
               VCS_ZCODE_SCIENCE_OK &&
           zproj_put(workspace, root_out, wire, sizeof(wire));
}

/* Seal + store one curation vote. Returns the canonical vote id. */
static bool zproj_put_vote(const char *workspace,
                           const uint8_t genesis_seed[32],
                           const uint8_t voter_seed[32],
                           const uint8_t property_root[32], uint8_t signal,
                           uint64_t sequence, int64_t expires_unix,
                           const uint8_t key_seed[32], uint8_t vote_id_out[32])
{
    uint8_t pubkey[32], secret[64];
    ed25519_keypair(pubkey, secret, key_seed);
    struct vcs_zcode_curation_vote_v1 vote;
    memset(&vote, 0, sizeof(vote));
    vote.schema_version = VCS_ZCODE_SCIENCE_VERSION;
    memcpy(vote.network_genesis_root, genesis_seed, 32);
    memcpy(vote.voter_zid_root, voter_seed, 32);
    memcpy(vote.property_root, property_root, 32);
    vote.signal = signal;
    vote.sequence = sequence;
    vote.expires_unix = expires_unix;
    uint8_t wire[VCS_ZCODE_CURATION_VOTE_WIRE_BYTES];
    return vcs_zcode_curation_vote_seal(&vote, secret, pubkey) ==
               VCS_ZCODE_SCIENCE_OK &&
           vcs_zcode_curation_vote_serialize(&vote, wire) ==
               VCS_ZCODE_SCIENCE_OK &&
           vcs_zcode_curation_vote_id(&vote, vote_id_out) ==
               VCS_ZCODE_SCIENCE_OK &&
           zproj_put(workspace, vote_id_out, wire, sizeof(wire));
}

/* Seal a vote, flip one signature byte, and store the tampered wire at its
 * own (tampered) canonical id: the index admits it (id agreement), the
 * projection's signature check must reject it. */
static bool zproj_put_tampered_vote(const char *workspace,
                                    const uint8_t genesis_seed[32],
                                    const uint8_t voter_seed[32],
                                    const uint8_t property_root[32],
                                    const uint8_t key_seed[32],
                                    uint8_t vote_id_out[32])
{
    uint8_t pubkey[32], secret[64];
    ed25519_keypair(pubkey, secret, key_seed);
    struct vcs_zcode_curation_vote_v1 vote;
    memset(&vote, 0, sizeof(vote));
    vote.schema_version = VCS_ZCODE_SCIENCE_VERSION;
    memcpy(vote.network_genesis_root, genesis_seed, 32);
    memcpy(vote.voter_zid_root, voter_seed, 32);
    memcpy(vote.property_root, property_root, 32);
    vote.signal = VCS_ZCODE_CURATION_USEFUL;
    vote.sequence = 1;
    vote.expires_unix = 5000;
    if (vcs_zcode_curation_vote_seal(&vote, secret, pubkey) !=
        VCS_ZCODE_SCIENCE_OK)
        return false;
    vote.signature[0] ^= 0xff;
    uint8_t wire[VCS_ZCODE_CURATION_VOTE_WIRE_BYTES];
    return vcs_zcode_curation_vote_serialize(&vote, wire) ==
               VCS_ZCODE_SCIENCE_OK &&
           vcs_zcode_curation_vote_id(&vote, vote_id_out) ==
               VCS_ZCODE_SCIENCE_OK &&
           zproj_put(workspace, vote_id_out, wire, sizeof(wire));
}

static void zproj_seed(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

struct zproj_rank_run {
    struct vcs_zcode_science_index *index;
    struct vcs_zcode_discovery_scan_v1 *scan;
    struct vcs_zcode_discovery_graph_v1 graph;
    struct vcs_zcode_discovery_rank_entry_v1 *entries;
    struct vcs_zcode_discovery_rank_result_v1 result;
    uint64_t residual;
};

static void zproj_run_free(struct zproj_rank_run *run)
{
    free(run->entries);
    vcs_zcode_discovery_graph_free(&run->graph);
    vcs_zcode_discovery_scan_free(run->scan);
    vcs_zcode_science_index_free(run->index);
    memset(run, 0, sizeof(*run));
}

/* index -> scan -> assemble -> compute over one workspace. */
static bool zproj_rank(const char *workspace, const uint8_t *genesis,
                       struct zproj_rank_run *run)
{
    memset(run, 0, sizeof(*run));
    uint8_t filter_root[32];
    zproj_root(filter_root, 9);
    bool ok = false;
    run->index = vcs_zcode_science_index_build(workspace, ZPROJ_NOW);
    if (!run->index)
        return false;
    run->scan = vcs_zcode_discovery_projection_scan(
        workspace, run->index, NULL, 0, genesis, ZPROJ_NOW);
    if (!run->scan)
        goto done;
    if (vcs_zcode_discovery_projection_assemble(run->scan, &run->graph) !=
        VCS_ZCODE_DISCOVERY_RANK_OK)
        goto done;
    if (run->graph.node_count == 0) {
        ok = true;
        goto done;
    }
    run->entries = zcl_malloc(
        sizeof(*run->entries) * run->graph.node_count, "zproj_test_entries");
    if (!run->entries)
        goto done;
    ok = vcs_zcode_discovery_projection_compute(
             &run->graph, filter_root, run->entries, &run->result,
             &run->residual) == VCS_ZCODE_DISCOVERY_RANK_OK;
done:
    if (!ok)
        zproj_run_free(run);
    return ok;
}

static uint64_t zproj_mass_sum(
    const struct vcs_zcode_discovery_rank_entry_v1 *entries, size_t count)
{
    uint64_t sum = 0;
    for (size_t i = 0; i < count; i++)
        sum += entries[i].mass;
    return sum;
}

/* The node index of the node whose root equals member, or SIZE_MAX. */
static size_t zproj_node_of(const struct zproj_rank_run *run,
                            const uint8_t member[32])
{
    for (size_t i = 0; i < run->graph.node_count; i++)
        if (memcmp(run->graph.nodes[i].property_root, member, 32) == 0)
            return i;
    return SIZE_MAX;
}

static bool zproj_graph_has_node(
    const struct vcs_zcode_discovery_graph_v1 *g, const uint8_t root[32])
{
    for (size_t i = 0; i < g->node_count; i++)
        if (memcmp(g->nodes[i].property_root, root, 32) == 0)
            return true;
    return false;
}

/* The representative (node) root of the lineage containing member — the
 * scan sorts each lineage's members, so members[0] is the node root — or
 * NULL when no lineage contains it. */
static const uint8_t *zproj_lineage_rep(
    const struct vcs_zcode_discovery_scan_v1 *scan, const uint8_t member[32])
{
    for (size_t i = 0; i < scan->lineage_count; i++)
        for (size_t m = 0; m < scan->lineages[i].member_count; m++)
            if (memcmp(scan->lineages[i].members[m], member, 32) == 0)
                return scan->lineages[i].members[0];
    return NULL;
}

/* ── 1: determinism + input-order invariance ─────────────────────── */

/* Mint the shared corpus: studies A/B/C with citation edges A->B, A->C,
 * B->C and the full vote zoo. Citation sets name FINAL study roots, so
 * they are built dependency-order (C's root is fixed; B's set cites C;
 * A's set cites B and C). Returns the study roots. */
static bool zproj_mint_corpus(const char *workspace, bool reverse,
                              uint8_t roots[3][32], uint8_t sources[3][32],
                              uint8_t genesis[32])
{
    struct vcs_zcode_study_spec_v1 studies[3];
    const uint8_t src_bytes[3] = {0xa1, 0xa2, 0xa3};
    for (size_t i = 0; i < 3; i++) {
        zproj_study(&studies[i], (uint8_t)(i + 1), src_bytes[i], i + 1);
        zproj_root(sources[i], src_bytes[i]);
    }
    zproj_root(genesis, 50);
    uint8_t payload[VCS_ZCODE_DISCOVERY_PROJECTION_MAX_CITATION_SET * 32u];
    size_t count = 0;
    /* C carries no citation object: its root is final. */
    if (vcs_zcode_study_spec_root(&studies[2], roots[2]) !=
        VCS_ZCODE_SCIENCE_OK)
        return false;
    /* B cites {C}: encode, point B at the set, finalize B's root. */
    if (!vcs_zcode_discovery_citation_set_encode(roots[2], 1, payload,
                                                 &count,
                                                 studies[1].citations_root))
        return false;
    if (!zproj_put(workspace, studies[1].citations_root, payload,
                   count * 32u))
        return false;
    if (vcs_zcode_study_spec_root(&studies[1], roots[1]) !=
        VCS_ZCODE_SCIENCE_OK)
        return false;
    /* A cites {B, C}. */
    uint8_t a_cited[2][32];
    memcpy(a_cited[0], roots[1], 32);
    memcpy(a_cited[1], roots[2], 32);
    if (!vcs_zcode_discovery_citation_set_encode(&a_cited[0][0], 2, payload,
                                                 &count,
                                                 studies[0].citations_root))
        return false;
    if (!zproj_put(workspace, studies[0].citations_root, payload,
                   count * 32u))
        return false;
    if (vcs_zcode_study_spec_root(&studies[0], roots[0]) !=
        VCS_ZCODE_SCIENCE_OK)
        return false;
    /* Insertion order must not matter: forward on one workspace, reverse
     * on the other. */
    size_t order[3] = {0, 1, 2};
    if (reverse) {
        order[0] = 2;
        order[2] = 0;
    }
    for (size_t k = 0; k < 3; k++) {
        uint8_t ignored[32];
        if (!zproj_put_study(workspace, &studies[order[k]], ignored))
            return false;
    }
    /* The vote zoo: valid USEFUL (voter A on B), valid INTERESTING
     * (voter B on C), expired (voter C on B), cross-network (voter D on B),
     * a voter+sequence replay pair (voter E on C, twice), a FLAG (voter F
     * on A), and a tampered signature (voter G on B). */
    uint8_t voter[32], key[32], id[32], alt_genesis[32];
    zproj_root(alt_genesis, 99);
    zproj_seed(voter, 51);
    zproj_seed(key, 61);
    if (!zproj_put_vote(workspace, genesis, voter, roots[1],
                        VCS_ZCODE_CURATION_USEFUL, 1, 5000, key, id))
        return false;
    zproj_seed(voter, 52);
    zproj_seed(key, 62);
    if (!zproj_put_vote(workspace, genesis, voter, roots[2],
                        VCS_ZCODE_CURATION_INTERESTING, 1, 5000, key, id))
        return false;
    zproj_seed(voter, 53);
    zproj_seed(key, 63);
    if (!zproj_put_vote(workspace, genesis, voter, roots[1],
                        VCS_ZCODE_CURATION_USEFUL, 1, 1500, key, id))
        return false; /* expired at ZPROJ_NOW */
    zproj_seed(voter, 54);
    zproj_seed(key, 64);
    if (!zproj_put_vote(workspace, alt_genesis, voter, roots[1],
                        VCS_ZCODE_CURATION_USEFUL, 1, 5000, key, id))
        return false; /* cross-network */
    zproj_seed(voter, 55);
    zproj_seed(key, 65);
    if (!zproj_put_vote(workspace, genesis, voter, roots[2],
                        VCS_ZCODE_CURATION_USEFUL, 7, 5000, key, id))
        return false; /* replay pair, first */
    if (!zproj_put_vote(workspace, genesis, voter, roots[2],
                        VCS_ZCODE_CURATION_USEFUL, 7, 4999, key, id))
        return false; /* replay pair, second (different expiry, same seq) */
    zproj_seed(voter, 56);
    zproj_seed(key, 66);
    if (!zproj_put_vote(workspace, genesis, voter, roots[0],
                        VCS_ZCODE_CURATION_FLAG, 1, 5000, key, id))
        return false; /* FLAG: never a seed */
    zproj_seed(voter, 57);
    zproj_seed(key, 67);
    if (!zproj_put_tampered_vote(workspace, genesis, voter, roots[1], key,
                                 id))
        return false;
    return true;
}

static int test_zproj_determinism(void)
{
    int failures = 0;
    TEST("zcode_discovery_projection: rebuild + admission-order invariance") {
        char dir_a[ZPROJ_DIR_CAP], dir_b[ZPROJ_DIR_CAP];
        ASSERT(zproj_setup(dir_a, sizeof(dir_a)));
        ASSERT(zproj_setup(dir_b, sizeof(dir_b)));
        uint8_t roots_a[3][32], roots_b[3][32], sources[3][32];
        uint8_t genesis_a[32], genesis_b[32];
        ASSERT(zproj_mint_corpus(dir_a, false, roots_a, sources, genesis_a));
        ASSERT(zproj_mint_corpus(dir_b, true, roots_b, sources, genesis_b));
        /* Same content: same study roots and genesis, regardless of the
         * order the objects were admitted in. */
        ASSERT(memcmp(roots_a, roots_b, sizeof(roots_a)) == 0);
        ASSERT(memcmp(genesis_a, genesis_b, 32) == 0);

        struct zproj_rank_run run_a, run_b, run_rebuild;
        ASSERT(zproj_rank(dir_a, genesis_a, &run_a));
        ASSERT(zproj_rank(dir_b, genesis_b, &run_b));
        ASSERT_EQ(run_a.graph.node_count, 3);
        ASSERT_EQ(run_a.graph.edge_count, 3);
        ASSERT_EQ(run_a.scan->votes_considered, 8);
        /* Accepted: the valid USEFUL, the valid INTERESTING, and ONE of
         * the replay pair. */
        ASSERT_EQ(run_a.scan->votes_accepted, 3);
        ASSERT_EQ(zproj_mass_sum(run_a.entries, run_a.graph.node_count),
                  VCS_ZCODE_DISCOVERY_RANK_MASS);
        /* Seeds: B carries 2 (USEFUL), C carries 3 (INTERESTING + one
         * replayed USEFUL); A carries none (FLAG never seeds). */
        ASSERT_EQ(run_a.graph.seed_count, 2);
        const uint8_t *rep_a = zproj_lineage_rep(run_a.scan, roots_a[0]);
        const uint8_t *rep_b = zproj_lineage_rep(run_a.scan, roots_a[1]);
        const uint8_t *rep_c = zproj_lineage_rep(run_a.scan, roots_a[2]);
        ASSERT(rep_a != NULL && rep_b != NULL && rep_c != NULL);
        size_t node_a = zproj_node_of(&run_a, rep_a);
        size_t node_b = zproj_node_of(&run_a, rep_b);
        size_t node_c = zproj_node_of(&run_a, rep_c);
        ASSERT(node_a != SIZE_MAX && node_b != SIZE_MAX &&
               node_c != SIZE_MAX);
        ASSERT_EQ(run_a.graph.node_seed_weight[node_a], 0);
        ASSERT_EQ(run_a.graph.node_seed_weight[node_b], 2);
        ASSERT_EQ(run_a.graph.node_seed_weight[node_c], 3);
        /* Direct citation counts: B cited once (A), C cited twice. */
        ASSERT_EQ(run_a.graph.in_degree[node_a], 0);
        ASSERT_EQ(run_a.graph.in_degree[node_b], 1);
        ASSERT_EQ(run_a.graph.in_degree[node_c], 2);

        /* Input-order invariance through the FULL projection: identical
         * roots, render order, and residual across the two workspaces. */
        ASSERT(memcmp(run_a.scan->corpus_root, run_b.scan->corpus_root,
                      32) == 0);
        ASSERT(memcmp(run_a.result.graph_root, run_b.result.graph_root,
                      32) == 0);
        ASSERT(memcmp(run_a.result.seed_set_root,
                      run_b.result.seed_set_root, 32) == 0);
        ASSERT(memcmp(run_a.entries, run_b.entries,
                      run_a.graph.node_count * sizeof(*run_a.entries)) == 0);
        ASSERT_EQ(run_a.residual, run_b.residual);

        /* Drop-and-rebuild from the same CAS: identical again. */
        ASSERT(zproj_rank(dir_a, genesis_a, &run_rebuild));
        ASSERT(memcmp(run_a.result.graph_root,
                      run_rebuild.result.graph_root, 32) == 0);
        ASSERT(memcmp(run_a.entries, run_rebuild.entries,
                      run_a.graph.node_count * sizeof(*run_a.entries)) == 0);
        ASSERT_EQ(run_a.residual, run_rebuild.residual);

        zproj_run_free(&run_a);
        zproj_run_free(&run_b);
        zproj_run_free(&run_rebuild);
        zproj_teardown(dir_a);
        zproj_teardown(dir_b);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2: version/fork collapse ────────────────────────────────────── */

static int test_zproj_collapse(void)
{
    int failures = 0;
    TEST("zcode_discovery_projection: versions and forks of one lineage rank as one node") {
        char dir[ZPROJ_DIR_CAP];
        ASSERT(zproj_setup(dir, sizeof(dir)));
        uint8_t src_x[32], src_y[32], src_z[32], src_q[32];
        zproj_root(src_x, 0xb1);
        zproj_root(src_y, 0xb2);
        zproj_root(src_z, 0xb3);
        zproj_root(src_q, 0xb4);
        /* study1 measures X; a candidate derived X->Y (version) and
         * another X->Z (fork), both referenced by study1's results. */
        struct vcs_zcode_study_spec_v1 s1, s2, s3, s4, s5;
        zproj_study(&s1, 1, 0xb1, 1);
        zproj_study(&s2, 2, 0xb2, 1);
        zproj_study(&s3, 3, 0xb3, 1);
        zproj_study(&s4, 4, 0xb4, 1);
        zproj_study(&s5, 5, 0xb4, 2); /* same source as s4: one lineage */
        struct vcs_zcode_candidate_v1 cxy, cxz;
        zproj_candidate(&cxy, 0x50, src_x, src_y);
        zproj_candidate(&cxz, 0x60, src_x, src_z);
        uint8_t cxy_root[32], cxz_root[32], ignored[32];
        ASSERT(zproj_put_candidate(dir, &cxy, cxy_root));
        ASSERT(zproj_put_candidate(dir, &cxz, cxz_root));
        uint8_t r1[32], r2[32];
        ASSERT(zproj_put_result(dir, &s1, cxy_root,
                                VCS_ZCODE_BENCHMARK_OBSERVED, 1, r1));
        ASSERT(zproj_put_result(dir, &s1, cxz_root,
                                VCS_ZCODE_BENCHMARK_OBSERVED, 2, r2));
        uint8_t root1[32], root4[32];
        ASSERT(zproj_put_study(dir, &s1, root1));
        ASSERT(zproj_put_study(dir, &s2, ignored));
        ASSERT(zproj_put_study(dir, &s3, ignored));
        ASSERT(zproj_put_study(dir, &s4, root4));
        ASSERT(zproj_put_study(dir, &s5, ignored));

        struct zproj_rank_run run;
        ASSERT(zproj_rank(dir, NULL, &run));
        /* {s1, s2, s3, X, Y, Z} collapse to ONE node; {s4, s5, Q} to a
         * second. */
        ASSERT_EQ(run.graph.node_count, 2);
        ASSERT_EQ(run.scan->lineage_count, 2);
        ASSERT_EQ(run.scan->lineages[0].study_count +
                  run.scan->lineages[1].study_count, 5);
        const uint8_t *merged_rep = zproj_lineage_rep(run.scan, root1);
        ASSERT(merged_rep != NULL);
        size_t merged = zproj_node_of(&run, merged_rep);
        ASSERT(merged != SIZE_MAX);
        /* Every member of the merged lineage names the same lineage rep. */
        const uint8_t *rep_x = zproj_lineage_rep(run.scan, src_x);
        const uint8_t *rep_y = zproj_lineage_rep(run.scan, src_y);
        const uint8_t *rep_z = zproj_lineage_rep(run.scan, src_z);
        const uint8_t *rep_q = zproj_lineage_rep(run.scan, src_q);
        ASSERT(rep_x != NULL && rep_y != NULL && rep_z != NULL &&
               rep_q != NULL);
        ASSERT(memcmp(rep_x, merged_rep, 32) == 0);
        ASSERT(memcmp(rep_y, merged_rep, 32) == 0);
        ASSERT(memcmp(rep_z, merged_rep, 32) == 0);
        ASSERT(memcmp(rep_q, merged_rep, 32) != 0);
        ASSERT(zproj_node_of(&run, rep_q) != SIZE_MAX);
        /* Mass still conserves over the collapsed graph. */
        ASSERT_EQ(zproj_mass_sum(run.entries, run.graph.node_count),
                  VCS_ZCODE_DISCOVERY_RANK_MASS);
        zproj_run_free(&run);
        zproj_teardown(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3: omission bound over 4096 properties ──────────────────────── */

static int test_zproj_omission(void)
{
    int failures = 0;
    TEST("zcode_discovery_projection: 4097 properties admit 4096 deterministically") {
        struct vcs_zcode_discovery_scan_v1 scan;
        memset(&scan, 0, sizeof(scan));
        const size_t total = VCS_ZCODE_DISCOVERY_RANK_MAX_NODES + 1u;
        struct vcs_zcode_discovery_lineage_v1 *lineages = zcl_calloc(
            total, sizeof(*lineages), "zproj_test_lineages");
        uint8_t(*members)[32] = zcl_calloc(total, sizeof(*members),
                                           "zproj_test_members");
        ASSERT(lineages != NULL && members != NULL);
        for (size_t i = 0; i < total; i++) {
            /* Deterministic distinct roots, already ascending (assemble
             * admits the first MAX_NODES lineages in scan order, which a
             * real scan guarantees root-sorted): byte 0 = index high,
             * byte 1 = index low, tail filled. */
            memset(members[i], 0x5c, 32);
            members[i][0] = (uint8_t)((i >> 8) & 0xffu);
            members[i][1] = (uint8_t)(i & 0xffu);
            lineages[i].members = &members[i];
            lineages[i].member_count = 1;
            lineages[i].study_count = 1;
        }
        scan.lineages = lineages;
        scan.lineage_count = total;

        struct vcs_zcode_discovery_graph_v1 g1, g2;
        ASSERT_EQ(vcs_zcode_discovery_projection_assemble(&scan, &g1),
                  VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT_EQ(g1.node_count, VCS_ZCODE_DISCOVERY_RANK_MAX_NODES);
        ASSERT_EQ(g1.omitted_node_count, 1);
        /* The omitted property is the largest root: the lineage built on
         * index 4096 (0x10,0x00 lead bytes > every 0..4095). */
        ASSERT(!zproj_graph_has_node(&g1, members[total - 1]));
        ASSERT(zproj_graph_has_node(&g1, members[total - 2]));
        /* Deterministic: a second assembly is byte-identical. */
        ASSERT_EQ(vcs_zcode_discovery_projection_assemble(&scan, &g2),
                  VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT_EQ(g2.omitted_node_count, 1);
        uint8_t root1[32], root2[32];
        ASSERT_EQ(vcs_zcode_discovery_graph_root(g1.nodes, g1.node_count,
                                                 g1.edges, g1.edge_count,
                                                 root1),
                  VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT_EQ(vcs_zcode_discovery_graph_root(g2.nodes, g2.node_count,
                                                 g2.edges, g2.edge_count,
                                                 root2),
                  VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT(memcmp(root1, root2, 32) == 0);
        vcs_zcode_discovery_graph_free(&g1);
        vcs_zcode_discovery_graph_free(&g2);
        free(members);
        free(lineages);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4: citation-spam cap ────────────────────────────────────────── */

static int test_zproj_citation_spam(void)
{
    int failures = 0;
    TEST("zcode_discovery_projection: citation spam caps at 64 edges per node") {
        char dir[ZPROJ_DIR_CAP];
        ASSERT(zproj_setup(dir, sizeof(dir)));
        /* One citing study and 100 cited studies. */
        const size_t cited_total = 100;
        struct vcs_zcode_study_spec_v1 spammer;
        zproj_study(&spammer, 1, 0xd1, 1);
        uint8_t spammer_root[32];
        ASSERT(zproj_put_study(dir, &spammer, spammer_root));
        uint8_t cited_roots[100][32];
        uint8_t expected[100][32]; /* the node root of each cited lineage */
        for (size_t i = 0; i < cited_total; i++) {
            struct vcs_zcode_study_spec_v1 cited;
            zproj_study(&cited, (uint8_t)(2 + i), 0xd2, i + 2);
            /* Distinct source roots that never collide with the field
             * fillers: 0xd2-filled, byte 1 distinguishing the study. */
            cited.source_root[1] = (uint8_t)i;
            ASSERT(zproj_put_study(dir, &cited, cited_roots[i]));
            /* The cited lineage's node root is its smallest member:
             * min(study root, source root). */
            memcpy(expected[i], cited_roots[i], 32);
            if (memcmp(cited.source_root, expected[i], 32) < 0)
                memcpy(expected[i], cited.source_root, 32);
        }
        uint8_t final_root[32];
        ASSERT(zproj_commit_citations(dir, &spammer, &cited_roots[0][0],
                                      cited_total, final_root));
        struct zproj_rank_run run;
        ASSERT(zproj_rank(dir, NULL, &run));
        ASSERT_EQ(run.graph.node_count, cited_total + 1u);
        /* Exactly 64 edges admitted, all from the spammer's node, to the
         * 64 smallest cited roots; 36 omitted and counted. */
        ASSERT_EQ(run.graph.edge_count,
                  VCS_ZCODE_DISCOVERY_PROJECTION_MAX_NODE_CITATIONS);
        ASSERT_EQ(run.graph.omitted_edge_count,
                  cited_total -
                      VCS_ZCODE_DISCOVERY_PROJECTION_MAX_NODE_CITATIONS);
        const uint8_t *spam_rep = zproj_lineage_rep(run.scan, final_root);
        ASSERT(spam_rep != NULL);
        size_t spam_node = zproj_node_of(&run, spam_rep);
        ASSERT(spam_node != SIZE_MAX);
        /* The admitted targets are the 64 smallest node roots among the
         * cited lineages. */
        qsort(expected, cited_total, 32, zproj_root_cmp);
        for (size_t e = 0; e < run.graph.edge_count; e++) {
            ASSERT(memcmp(run.graph.edges[e].citing_property_root,
                          run.graph.nodes[spam_node].property_root,
                          32) == 0);
            bool among_kept = false;
            for (size_t k = 0;
                 k < VCS_ZCODE_DISCOVERY_PROJECTION_MAX_NODE_CITATIONS; k++)
                if (memcmp(run.graph.edges[e].cited_property_root,
                           expected[k], 32) == 0)
                    among_kept = true;
            ASSERT(among_kept);
        }
        /* The 65th smallest cited node root was deterministically omitted. */
        for (size_t e = 0; e < run.graph.edge_count; e++)
            ASSERT(memcmp(run.graph.edges[e].cited_property_root,
                          expected[VCS_ZCODE_DISCOVERY_PROJECTION_MAX_NODE_CITATIONS],
                          32) != 0);
        /* Deterministic omission: a rebuild yields the identical edge set
         * and graph root. */
        struct zproj_rank_run rerun;
        ASSERT(zproj_rank(dir, NULL, &rerun));
        ASSERT(memcmp(run.result.graph_root, rerun.result.graph_root,
                      32) == 0);
        ASSERT_EQ(rerun.graph.omitted_edge_count,
                  run.graph.omitted_edge_count);
        zproj_run_free(&run);
        zproj_run_free(&rerun);
        zproj_teardown(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5: vote aggregation ─────────────────────────────────────────── */

static int test_zproj_votes(void)
{
    int failures = 0;
    TEST("zcode_discovery_projection: only verified live in-network votes seed, replays count once") {
        char dir[ZPROJ_DIR_CAP];
        ASSERT(zproj_setup(dir, sizeof(dir)));
        struct vcs_zcode_study_spec_v1 p, q;
        zproj_study(&p, 1, 0xe1, 1);
        zproj_study(&q, 2, 0xe2, 1);
        uint8_t root_p[32], root_q[32];
        ASSERT(zproj_put_study(dir, &p, root_p));
        ASSERT(zproj_put_study(dir, &q, root_q));
        uint8_t genesis[32], voter[32], key[32], id[32];
        zproj_root(genesis, 50);
        /* voter A: USEFUL on P (seq 1) then USEFUL on P again (seq 2) —
         * one voter, one lineage: the second never doubles the weight. */
        zproj_seed(voter, 51);
        zproj_seed(key, 61);
        ASSERT(zproj_put_vote(dir, genesis, voter, root_p,
                              VCS_ZCODE_CURATION_USEFUL, 1, 5000, key, id));
        ASSERT(zproj_put_vote(dir, genesis, voter, root_p,
                              VCS_ZCODE_CURATION_USEFUL, 2, 5000, key, id));
        /* voter B: INTERESTING on P. */
        zproj_seed(voter, 52);
        zproj_seed(key, 62);
        ASSERT(zproj_put_vote(dir, genesis, voter, root_p,
                              VCS_ZCODE_CURATION_INTERESTING, 1, 5000, key,
                              id));
        /* voter C: USEFUL on P, expired. */
        zproj_seed(voter, 53);
        zproj_seed(key, 63);
        ASSERT(zproj_put_vote(dir, genesis, voter, root_p,
                              VCS_ZCODE_CURATION_USEFUL, 1, 1500, key, id));
        /* voter D: INTERESTING on P, cross-network. */
        uint8_t alt_genesis[32];
        zproj_root(alt_genesis, 99);
        zproj_seed(voter, 54);
        zproj_seed(key, 64);
        ASSERT(zproj_put_vote(dir, alt_genesis, voter, root_p,
                              VCS_ZCODE_CURATION_INTERESTING, 1, 5000, key,
                              id));
        /* voter E: FLAG on P (never a seed). */
        zproj_seed(voter, 55);
        zproj_seed(key, 65);
        ASSERT(zproj_put_vote(dir, genesis, voter, root_p,
                              VCS_ZCODE_CURATION_FLAG, 1, 5000, key, id));
        /* voter F: tampered signature on P. */
        zproj_seed(voter, 56);
        zproj_seed(key, 66);
        ASSERT(zproj_put_tampered_vote(dir, genesis, voter, root_p, key,
                                       id));
        /* voter G: a voter+sequence replay pair on Q. */
        zproj_seed(voter, 57);
        zproj_seed(key, 67);
        ASSERT(zproj_put_vote(dir, genesis, voter, root_q,
                              VCS_ZCODE_CURATION_USEFUL, 9, 5000, key, id));
        ASSERT(zproj_put_vote(dir, genesis, voter, root_q,
                              VCS_ZCODE_CURATION_USEFUL, 9, 4999, key, id));

        struct zproj_rank_run run;
        ASSERT(zproj_rank(dir, genesis, &run));
        ASSERT_EQ(run.graph.node_count, 2);
        ASSERT_EQ(run.scan->votes_considered, 9);
        /* Accepted: A(seq1), B, one of G's replay pair. */
        ASSERT_EQ(run.scan->votes_accepted, 3);
        const uint8_t *rep_p = zproj_lineage_rep(run.scan, root_p);
        const uint8_t *rep_q = zproj_lineage_rep(run.scan, root_q);
        ASSERT(rep_p != NULL && rep_q != NULL);
        size_t node_p = zproj_node_of(&run, rep_p);
        size_t node_q = zproj_node_of(&run, rep_q);
        ASSERT(node_p != SIZE_MAX && node_q != SIZE_MAX);
        /* P: 2 (A's USEFUL, counted once) + 1 (B's INTERESTING) = 3.
         * Q: 2 (one of G's pair). */
        ASSERT_EQ(run.graph.node_seed_weight[node_p], 3);
        ASSERT_EQ(run.graph.node_seed_weight[node_q], 2);
        ASSERT_EQ(run.graph.seed_count, 2);
        /* Without the network identity no vote verifies: no seeds at
         * all, and the seed-set root changes. */
        struct zproj_rank_run unverified;
        ASSERT(zproj_rank(dir, NULL, &unverified));
        ASSERT_EQ(unverified.graph.seed_count, 0);
        ASSERT_EQ(unverified.scan->votes_accepted, 0);
        ASSERT(memcmp(run.result.seed_set_root,
                      unverified.result.seed_set_root, 32) != 0);
        zproj_run_free(&run);
        zproj_run_free(&unverified);
        zproj_teardown(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6: mechanical firewall ──────────────────────────────────────── */

static int test_zproj_firewall(void)
{
    int failures = 0;
    TEST("zcode_discovery_projection: rank never feeds evidence admission") {
        struct node_db ndb = {0};
        char dir[ZPROJ_DIR_CAP];
        ASSERT(zproj_setup_db(&ndb, dir, sizeof(dir)));
        /* A valid study + valid benchmark evidence, admitted through the
         * real S3 service path. */
        struct vcs_zcode_study_spec_v1 study;
        zproj_study(&study, 1, 0xf1, 1);
        uint8_t study_wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
        uint8_t study_root[32];
        ASSERT_EQ(vcs_zcode_study_spec_serialize(&study, study_wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_study_spec_root(&study, study_root),
                  VCS_ZCODE_SCIENCE_OK);
        struct zcode_science_plan_out plan;
        struct zcode_science_commit_out commit;
        ASSERT(zcode_science_study_plan(&ndb, dir, study_wire,
                                        sizeof(study_wire), 1500,
                                        &plan).ok);
        ASSERT(zcode_science_study_commit(&ndb, dir, study_wire,
                                          sizeof(study_wire), true, 1500,
                                          &commit).ok);
        /* Evidence context: task + candidate wires in CAS (the admission
         * path loads them), method + profile objects via work.plan. */
        struct vcs_zcode_task_v1 task;
        struct vcs_zcode_candidate_v1 candidate;
        memset(&task, 0, sizeof(task));
        task.schema_version = VCS_ZCODE_DEV_VERSION;
        memcpy(task.source_root, study.source_root, 32);
        memcpy(task.dependency_lock_root, study.dependency_lock_root, 32);
        memcpy(task.toolchain_capsule_root, study.toolchain_capsule_root,
               32);
        zproj_root(task.write_scope_root, 20);
        zproj_root(task.acceptance_tests_root, 21);
        zproj_root(task.proof_policy_root, 22);
        zproj_root(task.model_policy_root, 23);
        memcpy(task.goal_root, study_root, 32);
        task.capabilities = VCS_ZCODE_TASK_CAP_V1_MASK;
        task.max_changed_files = 32;
        task.max_patch_bytes = 1024 * 1024;
        task.max_context_bytes = 2 * 1024 * 1024;
        task.max_cpu_seconds = 120;
        task.max_memory_bytes = UINT64_C(512) * 1024 * 1024;
        task.max_output_bytes = UINT64_C(64) * 1024 * 1024;
        task.expires_unix = study.expires_unix;
        uint8_t task_root[32];
        ASSERT_EQ(vcs_zcode_task_root(&task, task_root), VCS_ZCODE_DEV_OK);
        memset(&candidate, 0, sizeof(candidate));
        candidate.schema_version = VCS_ZCODE_DEV_VERSION;
        memcpy(candidate.task_root, task_root, 32);
        memcpy(candidate.base_source_root, task.source_root, 32);
        zproj_root(candidate.patch_root, 24);
        zproj_root(candidate.candidate_source_root, 25);
        zproj_root(candidate.adapter_policy_root, 26);
        zproj_root(candidate.author_pubkey, 27);
        candidate.sequence = 1;
        candidate.created_unix = 1100;
        uint8_t candidate_root[32], task_root_check[32];
        {
            uint8_t twire[VCS_ZCODE_TASK_WIRE_BYTES];
            uint8_t cwire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
            ASSERT_EQ(vcs_zcode_task_serialize(&task, twire),
                      VCS_ZCODE_DEV_OK);
            ASSERT_EQ(vcs_zcode_task_root(&task, task_root_check),
                      VCS_ZCODE_DEV_OK);
            ASSERT_EQ(vcs_zcode_candidate_serialize(&candidate, cwire),
                      VCS_ZCODE_DEV_OK);
            ASSERT_EQ(vcs_zcode_candidate_root(&candidate, candidate_root),
                      VCS_ZCODE_DEV_OK);
            ASSERT(zproj_put(dir, task_root, twire, sizeof(twire)));
            ASSERT(zproj_put(dir, candidate_root, cwire, sizeof(cwire)));
        }
        struct vcs_zcode_benchmark_method_v1 method;
        struct vcs_zcode_hardware_profile_v1 profile;
        struct vcs_build_action_v1 action;
        memset(&method, 0, sizeof(method));
        method.schema_version = VCS_ZCODE_BENCHMARK_METHOD_VERSION;
        zproj_root(method.workload_root, 0x41);
        zproj_root(method.timer_root, 0x42);
        zproj_root(method.estimator_root, 0x43);
        method.tolerance_ppm = 5000;
        method.warmup_samples = 10;
        method.measured_samples = 1000;
        method.sample_distribution = VCS_ZCODE_SAMPLE_DIST_TRIMMED_MEAN;
        method.trim_percent = 10;
        memset(&profile, 0, sizeof(profile));
        profile.schema_version = VCS_ZCODE_HARDWARE_PROFILE_VERSION;
        memcpy(profile.cpu_vendor, "GenuineIntel", 12);
        profile.physical_cores = 8;
        profile.logical_cores = 16;
        profile.ram_mib = 32768;
        profile.isa_bits = VCS_ZCODE_HW_ISA_AVX2;
        memcpy(profile.os_sysname, "Linux", 5);
        memcpy(profile.os_machine, "x86_64", 6);
        memcpy(profile.os_release, "6.9.0-test", 10);
        profile.tsc_freq_hz = UINT64_C(3000000000);
        memcpy(profile.timer_source, "tsc", 3);
        profile.captured_unix = 1000;
        memset(&action, 0, sizeof(action));
        zproj_root(action.source_sha256, 60);
        zproj_root(action.source_cas_sha3, 61);
        zproj_root(action.input_root_sha3, 62);
        zproj_root(action.toolchain_capsule_sha3, 63);
        ASSERT(vcs_build_action_v1_fixed_flags_root_for_kind(
                   VCS_BUILD_ACTION_KIND_BENCHMARK_V1, action.flags_sha3));
        ASSERT(vcs_build_action_v1_fixed_environment_root_for_kind(
                   VCS_BUILD_ACTION_KIND_BENCHMARK_V1,
                   action.environment_sha3));
        (void)snprintf(action.target, sizeof(action.target), "%s",
                       VCS_BUILD_TARGET_V1);
        (void)snprintf(action.profile, sizeof(action.profile), "science");
        const char *workdir = NULL, *output = NULL, *policy = NULL;
        ASSERT(vcs_build_action_v1_descriptors(
                   VCS_BUILD_ACTION_KIND_BENCHMARK_V1, &workdir, &output,
                   &policy));
        (void)snprintf(action.virtual_workdir,
                       sizeof(action.virtual_workdir), "%s", workdir);
        (void)snprintf(action.declared_outputs,
                       sizeof(action.declared_outputs), "%s", output);
        (void)snprintf(action.resource_policy,
                       sizeof(action.resource_policy), "%s", policy);
        action.sequence = 1;
        uint8_t mwire[VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES];
        uint8_t pwire[VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_benchmark_method_serialize(&method, mwire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_hardware_profile_serialize(&profile, pwire),
                  VCS_ZCODE_SCIENCE_OK);

        /* Result #1 commits (the admission path's baseline). */
        struct vcs_zcode_benchmark_result_v2 result1;
        memset(&result1, 0, sizeof(result1));
        result1.schema_version = VCS_ZCODE_BENCHMARK_RESULT_V2_VERSION;
        memcpy(result1.study_root, study_root, 32);
        memcpy(result1.task_root, task_root, 32);
        memcpy(result1.candidate_root, candidate_root, 32);
        ASSERT(vcs_build_action_v1_root_for_kind(
                   VCS_BUILD_ACTION_KIND_BENCHMARK_V1, &action,
                   result1.action_root) != 0);
        zproj_root(result1.achieved_environment_root, 31);
        zproj_root(result1.raw_sample_root, 32);
        zproj_root(result1.evidence_root, 33);
        result1.status = VCS_ZCODE_BENCHMARK_OBSERVED;
        result1.challenge_block_height = 3200000;
        zproj_root(result1.challenge_block_hash, 34);
        result1.sequence = 1;
        result1.started_unix = 1200;
        result1.finished_unix = 1300;
        ASSERT_EQ(vcs_zcode_benchmark_method_root(&method,
                                                  result1.method_root),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_hardware_profile_root(
                      &profile, result1.hardware_profile_root),
                  VCS_ZCODE_SCIENCE_OK);
        uint8_t wire1[VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_serialize(&result1, wire1),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT(zcode_science_work_plan(&ndb, dir, wire1, sizeof(wire1),
                                       mwire, sizeof(mwire), pwire,
                                       sizeof(pwire), &action, 1500,
                                       &plan).ok);
        ASSERT(zcode_science_work_commit(&ndb, dir, wire1, sizeof(wire1),
                                         &action, true, 1500, &commit).ok);

        /* Populate a rank that FLAGS the valid result's lineage: FLAG-only
         * votes give the node zero seed weight. */
        uint8_t genesis[32], voter[32], key[32], vote_id[32];
        zproj_root(genesis, 50);
        zproj_seed(voter, 51);
        zproj_seed(key, 61);
        ASSERT(zproj_put_vote(dir, genesis, voter, study_root,
                              VCS_ZCODE_CURATION_FLAG, 1, 5000, key,
                              vote_id));
        int objects_before = zproj_cas_object_count(dir);
        ASSERT(objects_before > 0);
        struct zproj_rank_run run;
        ASSERT(zproj_rank(dir, genesis, &run));
        ASSERT_EQ(run.graph.node_count, 1);
        ASSERT_EQ(run.graph.seed_count, 0); /* flagged: no seed weight */
        ASSERT_EQ(run.scan->votes_accepted, 0);
        ASSERT_EQ(zproj_mass_sum(run.entries, run.graph.node_count),
                  VCS_ZCODE_DISCOVERY_RANK_MASS);
        /* The projection is a read-only consumer: scanning and ranking
         * stored nothing. */
        ASSERT_EQ(zproj_cas_object_count(dir), objects_before);

        /* THE FIREWALL: with the flagging rank populated, a second valid
         * result commits unchanged — same wire, same root, admission
         * unaffected. */
        struct vcs_zcode_benchmark_result_v2 result2 = result1;
        result2.sequence = 2;
        zproj_root(result2.evidence_root, 35);
        uint8_t wire2[VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES];
        uint8_t expected_root2[32];
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_serialize(&result2, wire2),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_root(&result2,
                                                     expected_root2),
                  VCS_ZCODE_SCIENCE_OK);
        char expected_hex[65];
        zcl_hex_encode(expected_root2, 32, expected_hex);
        struct zcode_science_plan_out plan2;
        ASSERT(zcode_science_work_plan(&ndb, dir, wire2, sizeof(wire2),
                                       mwire, sizeof(mwire), pwire,
                                       sizeof(pwire), &action, 1500,
                                       &plan2).ok);
        ASSERT(zcode_science_work_commit(&ndb, dir, wire2, sizeof(wire2),
                                         &action, true, 1500, &commit).ok);
        ASSERT_STR_EQ(commit.result_root, expected_hex);
        node_db_close(&ndb);
        zproj_run_free(&run);
        zproj_teardown(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 7: command smoke ────────────────────────────────────────────── */

static bool zproj_reply_ok(const struct zcl_command_reply *reply)
{
    return reply->exit_code == ZCL_COMMAND_EXIT_OK &&
           reply->error.code[0] == '\0';
}

static int test_zproj_commands(void)
{
    int failures = 0;
    TEST("zcode_discovery_projection: discover renders explanations, snapshot is cheap") {
        struct node_db ndb = {0};
        char dir[ZPROJ_DIR_CAP];
        ASSERT(zproj_setup_db(&ndb, dir, sizeof(dir)));
        /* Commit a study through the service so the SQL projection row
         * exists, then add a second study + a vote straight to the CAS. */
        struct vcs_zcode_study_spec_v1 study, other;
        zproj_study(&study, 1, 0xc1, 1);
        uint8_t study_wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
        uint8_t study_root[32];
        ASSERT_EQ(vcs_zcode_study_spec_serialize(&study, study_wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_study_spec_root(&study, study_root),
                  VCS_ZCODE_SCIENCE_OK);
        struct zcode_science_plan_out plan;
        struct zcode_science_commit_out commit;
        ASSERT(zcode_science_study_plan(&ndb, dir, study_wire,
                                        sizeof(study_wire), 1500,
                                        &plan).ok);
        ASSERT(zcode_science_study_commit(&ndb, dir, study_wire,
                                          sizeof(study_wire), true, 1500,
                                          &commit).ok);
        node_db_close(&ndb);
        zproj_study(&other, 2, 0xc2, 1);
        uint8_t other_root[32];
        ASSERT(zproj_put_study(dir, &other, other_root));
        uint8_t genesis[32], voter[32], key[32], vote_id[32];
        zproj_root(genesis, 50);
        zproj_seed(voter, 51);
        zproj_seed(key, 61);
        ASSERT(zproj_put_vote(dir, genesis, voter, other_root,
                              VCS_ZCODE_CURATION_USEFUL, 1, 5000, key,
                              vote_id));
        char genesis_hex[65];
        zcl_hex_encode(genesis, 32, genesis_hex);

        /* zcode.science.discover, category=active: the SQL filter admits
         * the committed study; the CAS-only study is outside the SQL
         * projection and therefore filtered out FIRST. */
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "datadir", dir);
        (void)json_push_kv_str(&input, "workspace", dir);
        (void)json_push_kv_str(&input, "category", "active");
        (void)json_push_kv_int(&input, "now_unix", 1500);
        (void)json_push_kv_str(&input, "network_genesis_root", genesis_hex);
        (void)json_push_kv_int(&input, "max", 8);
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_science_discover.v1");
        zcl_native_handle_zcode_science_discover(&request, &reply);
        ASSERT(zproj_reply_ok(&reply));
        const struct json_value *count = json_get(&reply.data, "count");
        ASSERT(count != NULL);
        ASSERT_EQ(json_get_int(count), 1);
        const struct json_value *nodes = json_get(&reply.data, "node_count");
        ASSERT(nodes != NULL);
        ASSERT_EQ(json_get_int(nodes), 1);
        ASSERT(json_get(&reply.data, "corpus_root") != NULL);
        ASSERT(json_get(&reply.data, "graph_root") != NULL);
        ASSERT(json_get(&reply.data, "seed_set_root") != NULL);
        ASSERT(json_get(&reply.data, "filter_policy_root") != NULL);
        ASSERT(json_get(&reply.data, "convergence_residual") != NULL);
        ASSERT(json_get(&reply.data, "omitted_node_count") != NULL);
        ASSERT(json_get(&reply.data, "truncated") != NULL);
        const struct json_value *entries = json_get(&reply.data, "entries");
        ASSERT(entries != NULL && entries->num_children == 1);
        ASSERT(json_get(&entries->children[0], "property_root") != NULL);
        ASSERT(json_get(&entries->children[0], "mass") != NULL);
        ASSERT(json_get(&entries->children[0],
                        "mass_share_millionths") != NULL);
        ASSERT(json_get(&entries->children[0], "direct_citations") != NULL);
        ASSERT(json_get(&entries->children[0], "seed_weight") != NULL);
        zcl_command_reply_free(&reply);

        /* category=retracted filters the committed study out: the empty
         * filtered corpus is an honest zero answer. */
        json_free(&input);
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "datadir", dir);
        (void)json_push_kv_str(&input, "workspace", dir);
        (void)json_push_kv_str(&input, "category", "retracted");
        (void)json_push_kv_int(&input, "now_unix", 1500);
        struct zcl_command_request request2 = { .input = &input };
        zcl_command_reply_init(&reply, "zcl.zcode_science_discover.v1");
        zcl_native_handle_zcode_science_discover(&request2, &reply);
        ASSERT(zproj_reply_ok(&reply));
        ASSERT_EQ(json_get_int(json_get(&reply.data, "count")), 0);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "node_count")), 0);
        zcl_command_reply_free(&reply);

        /* A bad category is a named refusal with an error body. */
        json_free(&input);
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "datadir", dir);
        (void)json_push_kv_str(&input, "workspace", dir);
        (void)json_push_kv_str(&input, "category", "bogus");
        struct zcl_command_request request3 = { .input = &input };
        zcl_command_reply_init(&reply, "zcl.zcode_science_discover.v1");
        zcl_native_handle_zcode_science_discover(&request3, &reply);
        ASSERT(!zproj_reply_ok(&reply));
        ASSERT_STR_EQ(reply.error.code, "BAD_CATEGORY");
        zcl_command_reply_free(&reply);
        json_free(&input);

        /* zcode.science.rank.snapshot: roots + counts, no entries. */
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "workspace", dir);
        (void)json_push_kv_str(&input, "network_genesis_root", genesis_hex);
        (void)json_push_kv_int(&input, "now_unix", 1500);
        struct zcl_command_request request4 = { .input = &input };
        zcl_command_reply_init(&reply, "zcl.zcode_science_rank_snapshot.v1");
        zcl_native_handle_zcode_science_rank_snapshot(&request4, &reply);
        ASSERT(zproj_reply_ok(&reply));
        ASSERT(json_get(&reply.data, "corpus_root") != NULL);
        ASSERT(json_get(&reply.data, "graph_root") != NULL);
        ASSERT(json_get(&reply.data, "seed_set_root") != NULL);
        ASSERT(json_get(&reply.data, "entries") == NULL);
        /* The snapshot sees the WHOLE CAS corpus (no SQL filter): both
         * studies, and the vote seeded the second. */
        ASSERT_EQ(json_get_int(json_get(&reply.data, "node_count")), 2);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "seed_count")), 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "votes_accepted")), 1);
        zcl_command_reply_free(&reply);

        /* A missing workspace is a named refusal. */
        json_free(&input);
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "workspace",
                               "/nonexistent/zcode/discovery");
        struct zcl_command_request request5 = { .input = &input };
        zcl_command_reply_init(&reply, "zcl.zcode_science_rank_snapshot.v1");
        zcl_native_handle_zcode_science_rank_snapshot(&request5, &reply);
        ASSERT(!zproj_reply_ok(&reply));
        ASSERT_STR_EQ(reply.error.code, "WORKSPACE_NOT_FOUND");
        zcl_command_reply_free(&reply);
        json_free(&input);

        zproj_teardown(dir);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_discovery_projection(void)
{
    int failures = 0;
    failures += test_zproj_determinism();
    failures += test_zproj_collapse();
    failures += test_zproj_omission();
    failures += test_zproj_citation_spam();
    failures += test_zproj_votes();
    failures += test_zproj_firewall();
    failures += test_zproj_commands();
    printf("=== zcode_discovery_projection: %d failures ===\n", failures);
    return failures;
}
