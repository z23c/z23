/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical shard/checkpoint/productivity corpus proofs. */
#include "test/test_core.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "vcs/zcode_c23_corpus.h"

#include <stdlib.h>
#include <string.h>

static const char shard_root_kat[] =
    "75b6c0fc6e6affe282a9ae3baeeb6424c36d95add766fd29ad2f0a42c872dcd7";
static const char checkpoint_50m_root_kat[] =
    "7528b88dc8793b2ac150cb2de15e0930ea72883d131512b1a3534fa5fc655dca";
static const char productivity_root_kat[] =
    "311f144c37b719d74cea628b9b6613262d1c7f8e838683ac1f54342236e7422a";

static void fill(uint8_t root[32], uint8_t value)
{
    memset(root, value, 32);
}

static void ordered_root(uint8_t root[32], uint16_t value)
{
    memset(root, 0, 32);
    root[30] = (uint8_t)(value >> 8);
    root[31] = (uint8_t)value;
}

static void counted_entry(struct vcs_zcode_c23_corpus_entry_v1 *entry,
                          uint16_t id, uint64_t production,
                          uint64_t tests, bool durable)
{
    memset(entry, 0, sizeof(*entry));
    ordered_root(entry->semantic_lineage_root, id);
    ordered_root(entry->release_root, (uint16_t)(id + 0x4000u));
    fill(entry->passport_root, 0x21);
    fill(entry->proof_root, 0x22);
    fill(entry->source_assignment_root, 0x23);
    fill(entry->admission_root, 0x24);
    if (durable) fill(entry->possession_root, 0x25);
    entry->release_sequence = id;
    entry->production_loc = production;
    entry->test_loc = tests;
    entry->physical_lines = production + tests + 3u;
    entry->unique_semantic_units = production + tests;
    entry->evidence_mask = VCS_ZCODE_C23_EVIDENCE_REQUIRED_MASK;
    entry->flags = VCS_ZCODE_C23_ENTRY_COUNTED |
        (durable ? VCS_ZCODE_C23_ENTRY_DURABLE : 0u);
}

static void excluded_entry(struct vcs_zcode_c23_corpus_entry_v1 *entry,
                           uint16_t id)
{
    memset(entry, 0, sizeof(*entry));
    ordered_root(entry->semantic_lineage_root, id);
    ordered_root(entry->release_root, (uint16_t)(id + 0x4000u));
    entry->release_sequence = id;
    entry->physical_lines = 17;
    entry->unique_semantic_units = 9;
    entry->exclusion_mask = VCS_ZCODE_C23_EXCLUDE_VENDOR;
}

static struct vcs_zcode_c23_corpus_shard_v1 shard_for(
    const struct vcs_zcode_c23_corpus_entry_v1 *entries, size_t count)
{
    struct vcs_zcode_c23_corpus_shard_v1 shard = {
        .schema_version = 1,
        .flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS,
        .entries = entries,
        .entry_count = count,
    };
    fill(shard.rules_root, 0x31);
    fill(shard.family_policy_root, 0x32);
    fill(shard.moderation_set_root, 0x33);
    return shard;
}

static int test_shard_codec_and_pages(void)
{
    int failures = 0;
    TEST("corpus shards round-trip with stable root cursors") {
        struct vcs_zcode_c23_corpus_entry_v1 entries[3];
        counted_entry(&entries[0], 1, 11, 3, true);
        counted_entry(&entries[1], 2, 7, 5, false);
        excluded_entry(&entries[2], 3);
        struct vcs_zcode_c23_corpus_shard_v1 shard = shard_for(entries, 3);
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_validate(&shard),
                  VCS_ZCODE_C23_OK);
        size_t wire_size = vcs_zcode_c23_corpus_shard_v1_wire_size(3);
        uint8_t *wire = zcl_malloc(wire_size, "test_c23_shard_wire");
        ASSERT(wire != NULL);
        size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_encode(
                      &shard, wire, wire_size, &wire_len), VCS_ZCODE_C23_OK);
        ASSERT_EQ(wire_len, wire_size);
        struct vcs_zcode_c23_corpus_entry_v1 decoded_entries[3];
        struct vcs_zcode_c23_corpus_shard_v1 decoded;
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_decode(
                      &decoded, decoded_entries, 3, wire, wire_len),
                  VCS_ZCODE_C23_OK);
        uint8_t first_root[32], second_root[32];
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_root(&shard, first_root),
                  VCS_ZCODE_C23_OK);
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_root(&decoded, second_root),
                  VCS_ZCODE_C23_OK);
        ASSERT(memcmp(first_root, second_root, 32) == 0);
        char hex[65]; zcl_hex_encode(first_root, 32, hex);
        printf("c23_corpus_shard.v1=%s\n", hex);
        uint8_t expected[32];
        ASSERT(zcl_hex_decode(shard_root_kat, expected, 32));
        ASSERT(memcmp(first_root, expected, 32) == 0);

        size_t first = 0, count = 0;
        struct vcs_zcode_c23_page_cursor_v1 next;
        bool more = false;
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_page(
                      &shard, NULL, 2, &first, &count, &next, &more),
                  VCS_ZCODE_C23_OK);
        ASSERT_EQ(first, 0); ASSERT_EQ(count, 2); ASSERT(more);
        ASSERT_EQ(next.next_index, 2);
        ASSERT(memcmp(next.shard_root, first_root, 32) == 0);
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_page(
                      &shard, &next, 2, &first, &count, &next, &more),
                  VCS_ZCODE_C23_OK);
        ASSERT_EQ(first, 2); ASSERT_EQ(count, 1); ASSERT(!more);
        struct vcs_zcode_c23_page_cursor_v1 wrong = {.next_index = 1};
        fill(wrong.shard_root, 0xff);
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_page(
                      &shard, &wrong, 2, &first, &count, &next, &more),
                  VCS_ZCODE_C23_CURSOR);
        entries[1].flags |= VCS_ZCODE_C23_ENTRY_DURABLE;
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_validate(&shard),
                  VCS_ZCODE_C23_ROOT);
        free(wire);
        PASS();
    } _test_next:;
    return failures;
}

static int test_shard_maximum(void)
{
    int failures = 0;
    TEST("a 4096-entry shard reconstructs exactly and 4097 is refused") {
        size_t n = VCS_ZCODE_C23_SHARD_ENTRY_MAX;
        struct vcs_zcode_c23_corpus_entry_v1 *entries = zcl_calloc(
            n, sizeof(*entries), "test_c23_max_shard_entries");
        ASSERT(entries != NULL);
        for (size_t i = 0; i < n; i++)
            counted_entry(&entries[i], (uint16_t)(i + 1u), 1, 1, true);
        struct vcs_zcode_c23_corpus_shard_v1 shard = shard_for(entries, n);
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_validate(&shard),
                  VCS_ZCODE_C23_OK);
        size_t wire_size = vcs_zcode_c23_corpus_shard_v1_wire_size(n);
        uint8_t *wire = zcl_malloc(wire_size, "test_c23_max_shard_wire");
        struct vcs_zcode_c23_corpus_entry_v1 *decoded_entries = zcl_calloc(
            n, sizeof(*decoded_entries), "test_c23_max_shard_decode");
        ASSERT(wire && decoded_entries);
        size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_encode(
                      &shard, wire, wire_size, &wire_len), VCS_ZCODE_C23_OK);
        struct vcs_zcode_c23_corpus_shard_v1 decoded;
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_decode(
                      &decoded, decoded_entries, n, wire, wire_len),
                  VCS_ZCODE_C23_OK);
        ASSERT_EQ(decoded.entry_count, n);
        ASSERT(memcmp(decoded.entries[n - 1u].semantic_lineage_root,
                      entries[n - 1u].semantic_lineage_root, 32) == 0);
        shard.entry_count = n + 1u;
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_validate(&shard),
                  VCS_ZCODE_C23_SIZE);
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_wire_size(n + 1u), 0);
        free(decoded_entries); free(wire); free(entries);
        PASS();
    } _test_next:;
    return failures;
}

static void checkpoint_binding(
    struct vcs_zcode_c23_checkpoint_shard_v1 *binding, uint8_t shard_id,
    uint16_t first, uint16_t last, uint64_t production, uint64_t tests,
    uint64_t durable)
{
    memset(binding, 0, sizeof(*binding));
    fill(binding->shard_root, shard_id);
    ordered_root(binding->first_lineage_root, first);
    ordered_root(binding->last_lineage_root, last);
    binding->entry_count = (uint64_t)last - first + 1u;
    binding->production_loc = production;
    binding->test_loc = tests;
    binding->durable_loc = durable;
    binding->physical_lines = production + tests + 10u;
    binding->unique_semantic_units = production + tests;
}

static void checkpoint_base(
    struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint,
    struct vcs_zcode_c23_checkpoint_shard_v1 bindings[2])
{
    memset(checkpoint, 0, sizeof(*checkpoint));
    checkpoint->schema_version = 1;
    checkpoint->flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS;
    checkpoint->sequence = 1;
    fill(checkpoint->rules_root, 0x41);
    fill(checkpoint->family_policy_root, 0x42);
    fill(checkpoint->moderation_set_root, 0x43);
    fill(checkpoint->replication_evidence_root, 0x44);
    checkpoint->cutoff_height = 1000;
    checkpoint->cutoff_mtp = 2000;
    checkpoint_binding(&bindings[0], 0x51, 1, 10,
                       UINT64_C(30000000), 0, UINT64_C(30000000));
    checkpoint_binding(&bindings[1], 0x52, 11, 20,
                       UINT64_C(25000000), UINT64_C(5000000),
                       UINT64_C(30000000));
    checkpoint->shards = bindings;
    checkpoint->shard_count = 2;
    checkpoint->total_entries = 20;
    checkpoint->production_loc = UINT64_C(55000000);
    checkpoint->test_loc = UINT64_C(5000000);
    checkpoint->durable_loc = UINT64_C(60000000);
    checkpoint->physical_lines = UINT64_C(60000020);
    checkpoint->unique_semantic_units = UINT64_C(60000000);
}

static int test_checkpoint_chain(void)
{
    int failures = 0;
    TEST("50M and 100M checkpoints are signed, durable and ancestry-bound") {
        struct vcs_zcode_c23_checkpoint_shard_v1 bindings[2];
        struct vcs_zcode_c23_corpus_checkpoint_v1 fifty;
        checkpoint_base(&fifty, bindings);
        fifty.milestone = VCS_ZCODE_C23_MILESTONE_50M;
        uint8_t seed[32]; fill(seed, 0x61);
        ASSERT_EQ(vcs_zcode_c23_corpus_checkpoint_v1_sign(&fifty, seed),
                  VCS_ZCODE_C23_OK);
        uint8_t fifty_root[32];
        ASSERT_EQ(vcs_zcode_c23_corpus_checkpoint_v1_root(
                      &fifty, fifty_root), VCS_ZCODE_C23_OK);
        char hex[65]; zcl_hex_encode(fifty_root, 32, hex);
        printf("c23_corpus_checkpoint_50m.v1=%s\n", hex);
        uint8_t expected[32];
        ASSERT(zcl_hex_decode(checkpoint_50m_root_kat, expected, 32));
        ASSERT(memcmp(fifty_root, expected, 32) == 0);
        size_t wire_size = vcs_zcode_c23_corpus_checkpoint_v1_wire_size(2);
        uint8_t *wire = zcl_malloc(wire_size, "test_c23_checkpoint_wire");
        ASSERT(wire != NULL);
        size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_c23_corpus_checkpoint_v1_encode(
                      &fifty, wire, wire_size, &wire_len), VCS_ZCODE_C23_OK);
        struct vcs_zcode_c23_checkpoint_shard_v1 decoded_bindings[2];
        struct vcs_zcode_c23_corpus_checkpoint_v1 decoded;
        ASSERT_EQ(vcs_zcode_c23_corpus_checkpoint_v1_decode(
                      &decoded, decoded_bindings, 2, wire, wire_len),
                  VCS_ZCODE_C23_OK);
        ASSERT_EQ(decoded.production_loc, fifty.production_loc);

        struct vcs_zcode_c23_checkpoint_shard_v1 next_bindings[2] = {
            bindings[0], bindings[1],
        };
        next_bindings[0].production_loc = UINT64_C(50000000);
        next_bindings[0].durable_loc = UINT64_C(50000000);
        next_bindings[0].physical_lines = UINT64_C(50000010);
        next_bindings[0].unique_semantic_units = UINT64_C(50000000);
        next_bindings[1].production_loc = UINT64_C(45000000);
        next_bindings[1].test_loc = UINT64_C(5000000);
        next_bindings[1].durable_loc = UINT64_C(50000000);
        next_bindings[1].physical_lines = UINT64_C(50000010);
        next_bindings[1].unique_semantic_units = UINT64_C(50000000);
        struct vcs_zcode_c23_corpus_checkpoint_v1 hundred = fifty;
        hundred.milestone = VCS_ZCODE_C23_MILESTONE_100M;
        hundred.sequence = 2;
        hundred.cutoff_height++;
        hundred.cutoff_mtp++;
        memcpy(hundred.predecessor_checkpoint_root, fifty_root, 32);
        memcpy(hundred.verified_50m_ancestor_root, fifty_root, 32);
        hundred.shards = next_bindings;
        hundred.production_loc = UINT64_C(95000000);
        hundred.test_loc = UINT64_C(5000000);
        hundred.durable_loc = UINT64_C(100000000);
        hundred.physical_lines = UINT64_C(100000020);
        hundred.unique_semantic_units = UINT64_C(100000000);
        ASSERT_EQ(vcs_zcode_c23_corpus_checkpoint_v1_sign(&hundred, seed),
                  VCS_ZCODE_C23_OK);
        ASSERT_EQ(vcs_zcode_c23_corpus_checkpoint_v1_verify_successor(
                      &fifty, &hundred), VCS_ZCODE_C23_OK);
        hundred.verified_50m_ancestor_root[0] ^= 1u;
        ASSERT_EQ(vcs_zcode_c23_corpus_checkpoint_v1_sign(&hundred, seed),
                  VCS_ZCODE_C23_OK);
        ASSERT_EQ(vcs_zcode_c23_corpus_checkpoint_v1_verify_successor(
                      &fifty, &hundred), VCS_ZCODE_C23_ANCESTRY);
        struct vcs_zcode_c23_corpus_checkpoint_v1 weak = fifty;
        weak.durable_loc = VCS_ZCODE_C23_FIRST_MILESTONE_LOC - 1u;
        ASSERT_EQ(vcs_zcode_c23_corpus_checkpoint_v1_sign(&weak, seed),
                  VCS_ZCODE_C23_POLICY);
        bindings[1].first_lineage_root[31] = 10;
        ASSERT_EQ(vcs_zcode_c23_corpus_checkpoint_v1_sign(&fifty, seed),
                  VCS_ZCODE_C23_ORDER);
        free(wire);
        PASS();
    } _test_next:;
    return failures;
}

static bool proof_accept(void *ctx,
                         const struct vcs_zcode_productivity_receipt_v1 *r)
{
    return ctx == r;
}

static bool proof_refuse(void *ctx,
                         const struct vcs_zcode_productivity_receipt_v1 *r)
{
    (void)ctx; (void)r;
    return false;
}

static int test_productivity_receipt(void)
{
    int failures = 0;
    TEST("productivity sharing requires the signed complete external chain") {
        struct vcs_zcode_productivity_receipt_v1 receipt = {
            .schema_version = 1,
            .flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS,
            .evidence_mask = VCS_ZCODE_PRODUCTIVITY_REQUIRED_MASK,
            .completed_height = 500,
            .completed_mtp = 600,
        };
        fill(receipt.work_root, 0x71);
        fill(receipt.acceptance_root, 0x72);
        fill(receipt.release_root, 0x73);
        fill(receipt.admission_root, 0x74);
        fill(receipt.package_root, 0x75);
        fill(receipt.checkpoint_root, 0x76);
        uint8_t seed[32]; fill(seed, 0x77);
        ASSERT_EQ(vcs_zcode_productivity_receipt_v1_sign(&receipt, seed),
                  VCS_ZCODE_C23_OK);
        uint8_t wire[VCS_ZCODE_PRODUCTIVITY_RECEIPT_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_productivity_receipt_v1_encode(
                      &receipt, wire, sizeof(wire), &wire_len),
                  VCS_ZCODE_C23_OK);
        struct vcs_zcode_productivity_receipt_v1 decoded;
        ASSERT_EQ(vcs_zcode_productivity_receipt_v1_decode(
                      &decoded, wire, wire_len), VCS_ZCODE_C23_OK);
        uint8_t root[32];
        ASSERT_EQ(vcs_zcode_productivity_receipt_v1_root(&decoded, root),
                  VCS_ZCODE_C23_OK);
        char hex[65]; zcl_hex_encode(root, 32, hex);
        printf("productivity_receipt.v1=%s\n", hex);
        uint8_t expected[32];
        ASSERT(zcl_hex_decode(productivity_root_kat, expected, 32));
        ASSERT(memcmp(root, expected, 32) == 0);
        struct vcs_zcode_productivity_verify_context_v1 verify = {
            .current_height = 501,
            .current_mtp = 601,
            .prove_chain = proof_refuse,
        };
        ASSERT(!vcs_zcode_productivity_receipt_v1_shareable(
            &receipt, &verify));
        verify.prove_chain = proof_accept;
        verify.prove_chain_ctx = &receipt;
        ASSERT(vcs_zcode_productivity_receipt_v1_shareable(
            &receipt, &verify));
        verify.current_height = 499;
        ASSERT(!vcs_zcode_productivity_receipt_v1_shareable(
            &receipt, &verify));
        wire[36] ^= 1u;
        ASSERT_EQ(vcs_zcode_productivity_receipt_v1_decode(
                      &decoded, wire, wire_len), VCS_ZCODE_C23_SIGNATURE);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_c23_corpus_projection(void)
{
    int failures = test_shard_codec_and_pages() + test_shard_maximum() +
                   test_checkpoint_chain() + test_productivity_receipt();
    printf("=== zcode_c23_corpus_projection: %d failures ===\n", failures);
    return failures;
}
