/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: accepted-root heuristic lifecycle state-machine adversarial tests. */
#include "vcs/zcode_heuristic_lifecycle.h"

#include "base/safe_alloc.h"
#include "crypto/ed25519.h"
#include "test/test_core.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_science.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HL_CHECK(name_, expression_) do {                              \
    if (expression_) {                                                 \
        printf("  zcode_heuristic_lifecycle: %s... OK\n", (name_)); \
    } else {                                                           \
        printf("  zcode_heuristic_lifecycle: %s... FAIL\n", (name_)); \
        failures++;                                                    \
    }                                                                  \
} while (0)

static void hlt_root(uint8_t out[32], uint8_t tag)
{
    memset(out, tag, 32);
}

static bool hlt_store(
    const char *workspace,
    const struct vcs_zcode_science_statement_v1 *statement,
    const struct vcs_zcode_science_relation_set_v1 *relations,
    uint8_t statement_root[32])
{
    uint8_t relation_wire[VCS_ZCODE_SCIENCE_RELATION_SET_MAX_WIRE_BYTES];
    uint8_t statement_wire[VCS_ZCODE_SCIENCE_STATEMENT_WIRE_BYTES];
    uint8_t relation_root[32];
    size_t relation_len = 0;
    return vcs_zcode_science_relation_set_serialize(
               relations, relation_wire, &relation_len) ==
               VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_relation_set_root(relations, relation_root) ==
               VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_statement_serialize(statement, statement_wire) ==
               VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_statement_root(statement, statement_root) ==
               VCS_ZCODE_SCIENCE_OK &&
        vcs_object_put_addressed(workspace, relation_root, relation_wire,
                                 relation_len) &&
        vcs_object_put_addressed(workspace, statement_root, statement_wire,
                                 sizeof(statement_wire));
}

static bool hlt_statement(
    struct vcs_zcode_science_statement_v1 *statement,
    struct vcs_zcode_science_relation_set_v1 *relations,
    uint8_t profile, uint8_t relation_type,
    const uint8_t predecessor_root[32], const uint8_t heuristic_root[32],
    uint8_t tag, const uint8_t secret[32], const uint8_t pubkey[32])
{
    memset(statement, 0, sizeof(*statement));
    memset(relations, 0, sizeof(*relations));
    relations->schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION;
    if (relation_type != 0) {
        relations->row_count = 1;
        relations->rows[0].type = relation_type;
        memcpy(relations->rows[0].statement_root, predecessor_root, 32);
    }
    statement->schema_version = VCS_ZCODE_SCIENCE_STATEMENT_VERSION;
    statement->profile = profile;
    statement->access = VCS_ZCODE_SCIENCE_ACCESS_PUBLIC;
    statement->privacy = VCS_ZCODE_SCIENCE_PRIVACY_PUBLIC;
    statement->redistribution =
        VCS_ZCODE_SCIENCE_REDISTRIBUTION_PERMITTED;
    statement->authorship = VCS_ZCODE_SCIENCE_AUTHORSHIP_SIGNED;
    if (relation_type != 0) {
        statement->relation_count = 1;
        statement->relation_types =
            VCS_ZCODE_SCIENCE_RELATION_MASK(relation_type);
    }
    memcpy(statement->subject_root, heuristic_root, 32);
    hlt_root(statement->predicate_body_root, 20);
    hlt_root(statement->profile_schema_root, tag);
    hlt_root(statement->provenance_root, (uint8_t)(tag + 1u));
    hlt_root(statement->activity_root, 21);
    hlt_root(statement->input_root, 22);
    hlt_root(statement->authorship_assertion_root, 23);
    hlt_root(statement->license_root, 24);
    hlt_root(statement->access_policy_root, 25);
    hlt_root(statement->privacy_policy_root, 26);
    hlt_root(statement->external_identifiers_root, 27);
    hlt_root(statement->citations_root, 28);
    if (vcs_zcode_science_relation_set_root(
            relations, statement->relations_root) != VCS_ZCODE_SCIENCE_OK)
        return false;
    statement->observed_unix = tag;
    return vcs_zcode_science_statement_seal(statement, secret, pubkey) ==
        VCS_ZCODE_SCIENCE_OK;
}

static void hlt_sort_roots(uint8_t roots[][32], size_t count)
{
    for (size_t i = 1; i < count; i++) {
        uint8_t root[32];
        memcpy(root, roots[i], 32);
        size_t at = i;
        while (at != 0 && memcmp(roots[at - 1u], root, 32) > 0) {
            memcpy(roots[at], roots[at - 1u], 32);
            at--;
        }
        memcpy(roots[at], root, 32);
    }
}

static void hlt_snapshot(
    struct vcs_zcode_heuristic_lifecycle_snapshot_v1 *snapshot,
    const uint8_t heuristic_root[32], const uint8_t signer[32],
    const uint8_t anchor_root[32], const uint8_t roots[][32], size_t count)
{
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->schema_version =
        VCS_ZCODE_HEURISTIC_LIFECYCLE_SNAPSHOT_VERSION;
    snapshot->statement_count = (uint16_t)count;
    hlt_root(snapshot->local_policy_root, 30);
    memcpy(snapshot->expected_signer, signer, 32);
    memcpy(snapshot->heuristic_root, heuristic_root, 32);
    if (count != 0) memcpy(snapshot->anchor_statement_root, anchor_root, 32);
    for (size_t i = 0; i < count; i++)
        memcpy(snapshot->statement_roots[i], roots[i], 32);
    hlt_sort_roots(snapshot->statement_roots, count);
}

static bool hlt_report_same(
    const struct vcs_zcode_heuristic_lifecycle_report *left,
    const struct vcs_zcode_heuristic_lifecycle_report *right)
{
    return left->status == right->status &&
        left->reason == right->reason &&
        left->complete == right->complete &&
        left->validated_count == right->validated_count &&
        memcmp(left->head_statement_root,
               right->head_statement_root, 32) == 0 &&
        memcmp(left->snapshot_root, right->snapshot_root, 32) == 0;
}

int test_zcode_heuristic_lifecycle(void)
{
    int failures = 0;
    char workspace[160];
    int n = snprintf(workspace, sizeof(workspace),
                     "test-tmp/zcode_heuristic_lifecycle_%d", (int)getpid());
    test_cleanup_tmpdir(workspace);
    bool setup = n > 0 && (size_t)n < sizeof(workspace) &&
        (mkdir("test-tmp", 0700) == 0 || access("test-tmp", F_OK) == 0) &&
        mkdir(workspace, 0700) == 0 && vcs_object_store_init(workspace);
    HL_CHECK("workspace-initializes", setup);
    if (!setup) return failures + 1;

    uint8_t seed[32], secret[32], pubkey[32], heuristic_root[32];
    hlt_root(seed, 40);
    hlt_root(heuristic_root, 41);
    ed25519_keypair(pubkey, secret, seed);
    struct vcs_zcode_science_statement_v1 statements[7];
    struct vcs_zcode_science_relation_set_v1 relations[7];
    uint8_t roots[7][32];
    bool built = hlt_statement(
            &statements[0], &relations[0], VCS_ZCODE_SCIENCE_PROFILE_RESULT,
            0, NULL, heuristic_root, 50, secret, pubkey) &&
        hlt_store(workspace, &statements[0], &relations[0], roots[0]);
    built = built && hlt_statement(
            &statements[1], &relations[1],
            VCS_ZCODE_SCIENCE_PROFILE_SUPERSESSION,
            VCS_ZCODE_SCIENCE_RELATION_SUPERSESSION, roots[0],
            heuristic_root, 51, secret, pubkey) &&
        hlt_store(workspace, &statements[1], &relations[1], roots[1]);
    built = built && hlt_statement(
            &statements[2], &relations[2],
            VCS_ZCODE_SCIENCE_PROFILE_RETRACTION,
            VCS_ZCODE_SCIENCE_RELATION_RETRACTION, roots[1],
            heuristic_root, 52, secret, pubkey) &&
        hlt_store(workspace, &statements[2], &relations[2], roots[2]);
    built = built && hlt_statement(
            &statements[3], &relations[3],
            VCS_ZCODE_SCIENCE_PROFILE_COUNTEREVIDENCE,
            VCS_ZCODE_SCIENCE_RELATION_CONFLICT, roots[0],
            heuristic_root, 53, secret, pubkey) &&
        hlt_store(workspace, &statements[3], &relations[3], roots[3]);
    built = built && hlt_statement(
            &statements[4], &relations[4],
            VCS_ZCODE_SCIENCE_PROFILE_REPLICATION,
            VCS_ZCODE_SCIENCE_RELATION_SUPPORT, roots[3],
            heuristic_root, 54, secret, pubkey) &&
        hlt_store(workspace, &statements[4], &relations[4], roots[4]);
    built = built && hlt_statement(
            &statements[5], &relations[5],
            VCS_ZCODE_SCIENCE_PROFILE_RETRACTION,
            VCS_ZCODE_SCIENCE_RELATION_RETRACTION, roots[0],
            heuristic_root, 55, secret, pubkey) &&
        hlt_store(workspace, &statements[5], &relations[5], roots[5]);
    uint8_t wrong_subject[32];
    hlt_root(wrong_subject, 99);
    built = built && hlt_statement(
            &statements[6], &relations[6],
            VCS_ZCODE_SCIENCE_PROFILE_SUPERSESSION,
            VCS_ZCODE_SCIENCE_RELATION_SUPERSESSION, roots[0],
            wrong_subject, 56, secret, pubkey) &&
        hlt_store(workspace, &statements[6], &relations[6], roots[6]);
    HL_CHECK("fixtures-seal-and-store", built);

    struct vcs_zcode_heuristic_lifecycle_snapshot_v1 snapshot;
    struct vcs_zcode_heuristic_lifecycle_report report;
    struct vcs_zcode_heuristic_lifecycle_report sentinel;
    memset(&sentinel, 0x6d, sizeof(sentinel));
    hlt_snapshot(&snapshot, heuristic_root, pubkey, NULL, NULL, 0);
    memset(&report, 0xa5, sizeof(report));
    HL_CHECK("empty-accepted-snapshot-is-undetermined",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) == VCS_ZCODE_ATTENTION_OK &&
             report.complete &&
             report.status ==
                 VCS_ZCODE_HEURISTIC_LIFECYCLE_UNDETERMINED &&
             report.reason == VCS_ZCODE_HEURISTIC_LIFECYCLE_REASON_EMPTY &&
             report.validated_count == 0);

    uint8_t accepted[4][32];
    memcpy(accepted[0], roots[0], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], accepted, 1);
    HL_CHECK("accepted-result-anchor-is-retained",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) == VCS_ZCODE_ATTENTION_OK &&
             report.complete &&
             report.status == VCS_ZCODE_HEURISTIC_LIFECYCLE_RETAINED &&
             memcmp(report.head_statement_root, roots[0], 32) == 0);

    memcpy(accepted[1], roots[1], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], accepted, 2);
    HL_CHECK("supersession-head-remains-retained",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) == VCS_ZCODE_ATTENTION_OK &&
             report.status == VCS_ZCODE_HEURISTIC_LIFECYCLE_RETAINED &&
             memcmp(report.head_statement_root, roots[1], 32) == 0);

    memcpy(accepted[2], roots[2], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], accepted, 3);
    struct vcs_zcode_heuristic_lifecycle_report linear_report;
    HL_CHECK("explicit-retraction-head-retires",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &linear_report) ==
                 VCS_ZCODE_ATTENTION_OK &&
             linear_report.status == VCS_ZCODE_HEURISTIC_LIFECYCLE_RETIRED &&
             memcmp(linear_report.head_statement_root, roots[2], 32) == 0);

    uint8_t counter_chain[2][32];
    memcpy(counter_chain[0], roots[3], 32);
    memcpy(counter_chain[1], roots[0], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0],
                 counter_chain, 2);
    report = sentinel;
    HL_CHECK("counterevidence-is-not-lifecycle-authority",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_EVIDENCE &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    uint8_t replication_chain[2][32];
    memcpy(replication_chain[0], roots[4], 32);
    memcpy(replication_chain[1], roots[3], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[3],
                 replication_chain, 2);
    report = sentinel;
    HL_CHECK("support-is-not-lifecycle-authority",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_EVIDENCE &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    uint8_t forked[3][32];
    memcpy(forked[0], roots[0], 32);
    memcpy(forked[1], roots[1], 32);
    memcpy(forked[2], roots[5], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], forked, 3);
    HL_CHECK("fork-is-complete-but-undetermined",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) == VCS_ZCODE_ATTENTION_OK &&
             report.complete &&
             report.status ==
                 VCS_ZCODE_HEURISTIC_LIFECYCLE_UNDETERMINED &&
             report.reason ==
                 VCS_ZCODE_HEURISTIC_LIFECYCLE_REASON_AMBIGUOUS &&
             memcmp(report.head_statement_root, (uint8_t[32]){0}, 32) == 0);

    uint8_t permuted[3][32];
    memcpy(permuted[0], roots[2], 32);
    memcpy(permuted[1], roots[0], 32);
    memcpy(permuted[2], roots[1], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], permuted, 3);
    HL_CHECK("construction-order-cannot-change-projection",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) == VCS_ZCODE_ATTENTION_OK &&
             hlt_report_same(&linear_report, &report));

    report = sentinel;
    snapshot.expected_signer[0] ^= 1u;
    HL_CHECK("wrong-local-signer-fails-atomically",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_EVIDENCE &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);
    snapshot.expected_signer[0] ^= 1u;

    uint8_t wrong_subject_chain[2][32];
    memcpy(wrong_subject_chain[0], roots[0], 32);
    memcpy(wrong_subject_chain[1], roots[6], 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0],
                 wrong_subject_chain, 2);
    report = sentinel;
    HL_CHECK("wrong-subject-row-fails-whole-fold",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_EVIDENCE &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    uint8_t absent_root[32];
    hlt_root(absent_root, 111);
    uint8_t absent_set[2][32];
    memcpy(absent_set[0], roots[0], 32);
    memcpy(absent_set[1], absent_root, 32);
    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], absent_set, 2);
    report = sentinel;
    HL_CHECK("missing-accepted-object-fails-atomically",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_EVIDENCE &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], accepted, 3);
    memcpy(snapshot.statement_roots[1], snapshot.statement_roots[0], 32);
    report = sentinel;
    HL_CHECK("duplicate-accepted-root-refuses",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_ORDER &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], accepted, 3);
    snapshot.statement_roots[3][0] = 1;
    report = sentinel;
    HL_CHECK("inactive-root-and-alias-refuse",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_ROOT &&
             memcmp(&report, &sentinel, sizeof(report)) == 0 &&
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot,
                 (struct vcs_zcode_heuristic_lifecycle_report *)&snapshot) ==
                 VCS_ZCODE_ATTENTION_ALIAS);

    hlt_snapshot(&snapshot, heuristic_root, pubkey, roots[0], accepted, 3);
    report = sentinel;
    zcl_alloc_fault_fail_next("heuristic_lifecycle");
    HL_CHECK("allocation-failure-is-atomic",
             vcs_zcode_heuristic_lifecycle_fold(
                 workspace, &snapshot, &report) ==
                 VCS_ZCODE_ATTENTION_CAS &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);
    zcl_alloc_fault_clear();

    test_cleanup_tmpdir(workspace);
    return failures;
}
