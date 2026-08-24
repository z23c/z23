/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Peer-vote retention tests for quorum_oracle_service. A vote is current
 * accepted-header evidence for one peer, not an append-only header history:
 * repeated tip advances by one busy peer must never evict another peer's live
 * mesh evidence before the declared TTL. */

#include "test/test_core.h"

#include "json/json.h"
#include "services/quorum_oracle_service.h"

#include <stdint.h>
#include <string.h>

static const char qot_hash_a[] =
    "11111111111111111111111111111111"
    "11111111111111111111111111111111";
static const char qot_hash_b[] =
    "22222222222222222222222222222222"
    "22222222222222222222222222222222";
static const char qot_hash_c[] =
    "33333333333333333333333333333333"
    "33333333333333333333333333333333";
static const char qot_invalid_hash[65] = "not-a-hash";

static const struct json_value *qot_vote_for_peer(
    const struct json_value *dump, uint32_t peer_id)
{
    const struct json_value *votes = json_get(dump, "peer_votes");
    if (!votes || votes->type != JSON_ARR)
        return NULL;
    for (size_t i = 0; i < json_size(votes); i++) {
        const struct json_value *vote = json_at(votes, i);
        if (json_get_int(json_get(vote, "source_id")) == (int64_t)peer_id)
            return vote;
    }
    return NULL;
}

static int test_peer_tip_updates_do_not_evict_other_peers(void)
{
    int failures = 0;
    TEST_CASE("quorum oracle retains one monotonic latest vote per peer")
    {
        quorum_oracle_peer_votes_reset_for_test();

        /* The old per-(peer,height) ring filled all 64 slots here. Adding
         * peer 8 then evicted only peer 7's oldest height, leaving 63 stale
         * rows for peer 7 and making live_peer_votes lie about uniqueness. */
        for (int height = 1; height <= 64; height++)
            quorum_oracle_record_peer_header_vote(7, height, qot_hash_a);
        quorum_oracle_record_peer_header_vote(8, 100, qot_hash_b);

        struct json_value dump = {0};
        ASSERT(quorum_oracle_dump_state_json(&dump, NULL));
        ASSERT_EQ(json_get_int(json_get(&dump, "live_peer_votes")), 2);
        ASSERT_EQ(json_size(json_get(&dump, "peer_votes")), (size_t)2);

        const struct json_value *p7 = qot_vote_for_peer(&dump, 7);
        const struct json_value *p8 = qot_vote_for_peer(&dump, 8);
        ASSERT(p7 != NULL);
        ASSERT(p8 != NULL);
        ASSERT_EQ(json_get_int(json_get(p7, "height")), 64);
        ASSERT_STR_EQ(json_get_str(json_get(p7, "hash")), qot_hash_a);
        ASSERT_EQ(json_get_int(json_get(p8, "height")), 100);
        json_free(&dump);

        /* Bounded historical repair must not downgrade or refresh the live
         * tip vote. Same-height evidence may replace its hash (a reorg), and
         * a higher accepted header advances it normally. */
        quorum_oracle_record_peer_header_vote(7, 32, qot_hash_b);
        quorum_oracle_record_peer_header_vote(7, 64, qot_hash_b);
        quorum_oracle_record_peer_header_vote(7, 65, qot_hash_c);

        json_init(&dump);
        ASSERT(quorum_oracle_dump_state_json(&dump, NULL));
        ASSERT_EQ(json_get_int(json_get(&dump, "live_peer_votes")), 2);
        p7 = qot_vote_for_peer(&dump, 7);
        ASSERT(p7 != NULL);
        ASSERT_EQ(json_get_int(json_get(p7, "height")), 65);
        ASSERT_STR_EQ(json_get_str(json_get(p7, "hash")), qot_hash_c);
        json_free(&dump);
    } TEST_END
    return failures;
}

static int test_invalid_votes_never_allocate_slots(void)
{
    int failures = 0;
    TEST_CASE("quorum oracle invalid votes allocate no peer evidence")
    {
        quorum_oracle_peer_votes_reset_for_test();
        quorum_oracle_record_peer_header_vote(0, 1, qot_hash_a);
        quorum_oracle_record_peer_header_vote(9, -1, qot_hash_a);
        quorum_oracle_record_peer_header_vote(9, 1, qot_invalid_hash);

        struct json_value dump = {0};
        ASSERT(quorum_oracle_dump_state_json(&dump, NULL));
        ASSERT_EQ(json_get_int(json_get(&dump, "live_peer_votes")), 0);
        ASSERT_EQ(json_size(json_get(&dump, "peer_votes")), (size_t)0);
        json_free(&dump);
    } TEST_END
    return failures;
}

int test_quorum_oracle(void)
{
    printf("\n=== Quorum oracle peer-vote tests ===\n");
    int failures = 0;
    failures += test_peer_tip_updates_do_not_evict_other_peers();
    failures += test_invalid_votes_never_allocate_slots();
    quorum_oracle_peer_votes_reset_for_test();
    return failures;
}
