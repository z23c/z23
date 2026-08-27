/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Pins the DHT-frame culpability model — every reject reason's
 * offence category AND ban weight, the four-state verdict classifier
 * including its enabled/session guards, and the composition-root drop
 * counter. The weights are load-bearing DoS policy: changing one changes
 * ban behaviour, so both halves of the mapping are pinned here. */

#include <net/peer_scoring.h>
#include <vcs/zcode_dht_service.h>

#include "config/boot_zcode_dht_frame_auth.h"
#include "test/test_core.h"

#include <string.h>

int test_zcode_dht_frame_auth(void) {
  int failures = 0;
  /* Row-per-reason pin: reason -> expected offence and exact weight.
   * static_assert keeps the table complete when the enum grows; a new
   * reason cannot pass until someone classifies it consciously (the
   * switches in frame_auth enumerate exhaustively for the same reason). */
    TEST("zcode dht frame auth: offence table covers every reason with "
         "pinned weights") {
      static const struct {
        enum vcs_zcode_dht_reject_reason reason;
        enum peer_offence offence;
        int weight;
      } rows[] = {
          {VCS_ZCODE_DHT_REJECT_MALFORMED, PEER_OFFENCE_INVALID_MESSAGE,
           10},
          {VCS_ZCODE_DHT_REJECT_PLAINTEXT, PEER_OFFENCE_NONE, 0},
          {VCS_ZCODE_DHT_REJECT_DELEGATION, PEER_OFFENCE_INVALID_PAYLOAD,
           20},
          {VCS_ZCODE_DHT_REJECT_IDENTITY, PEER_OFFENCE_INVALID_PROOF,
           100},
          {VCS_ZCODE_DHT_REJECT_SIGNATURE, PEER_OFFENCE_INVALID_PROOF,
           100},
          {VCS_ZCODE_DHT_REJECT_SESSION, PEER_OFFENCE_INVALID_MESSAGE, 10},
          {VCS_ZCODE_DHT_REJECT_REPLAY, PEER_OFFENCE_INVALID_PROOF, 100},
          {VCS_ZCODE_DHT_REJECT_UNSOLICITED, PEER_OFFENCE_UNREQUESTED, 10},
          {VCS_ZCODE_DHT_REJECT_EXPIRED, PEER_OFFENCE_TIMEOUT, 5},
          {VCS_ZCODE_DHT_REJECT_POISONED, PEER_OFFENCE_INVALID_PROOF, 100},
          {VCS_ZCODE_DHT_REJECT_RATE, PEER_OFFENCE_FLOOD, 20},
          {VCS_ZCODE_DHT_REJECT_CAP, PEER_OFFENCE_FLOOD, 20},
          {VCS_ZCODE_DHT_REJECT_UNAUTHORIZED,
           PEER_OFFENCE_INVALID_PAYLOAD, 20},
          {VCS_ZCODE_DHT_REJECT_BACKPRESSURE, PEER_OFFENCE_NONE, 0},
      };
      static_assert(sizeof(rows) / sizeof(rows[0]) ==
                        VCS_ZCODE_DHT_REJECT_COUNT,
                    "reject table must cover every published reason");
      for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        enum peer_offence got = boot_zcode_dht_offence(rows[i].reason);
        ASSERT_EQ(got, rows[i].offence);
        /* The scorer only reads weights, so pin both halves. */
        ASSERT_EQ(peer_offence_weight(got), rows[i].weight);
        if (got == PEER_OFFENCE_NONE)
          ASSERT_EQ(peer_offence_weight(got), 0);
      }
      /* RATE and quota CAP are the same causal claim about a sender and
       * stay in one flood family; BACKPRESSURE is our own egress failing
       * and scores none. */
      ASSERT_EQ(boot_zcode_dht_offence(VCS_ZCODE_DHT_REJECT_RATE),
                boot_zcode_dht_offence(VCS_ZCODE_DHT_REJECT_CAP));
    }
    TEST("zcode dht frame auth: verdict classifier declines infra "
         "non-answers and refutes only crypto evidence") {
      const bool yes = true, no = false;
      /* Accepted frames authorize regardless of any other flag. */
      ASSERT_EQ((int)boot_zcode_dht_frame_classify(
                    yes, no, no, no, VCS_ZCODE_DHT_REJECT_MALFORMED),
                (int)BOOT_FRAME_AUTHORIZED);
      uint64_t drops = boot_zcode_dht_frame_auth_local_drops();
      /* Absent, disabled, and sessionless services decline quietly even
       * when the reject reason looks incriminating. */
      ASSERT_EQ((int)boot_zcode_dht_frame_classify(
                    no, no, yes, yes, VCS_ZCODE_DHT_REJECT_IDENTITY),
                (int)BOOT_FRAME_INFRA_NON_ANSWER);
      ASSERT_EQ((int)boot_zcode_dht_frame_classify(
                    no, yes, no, yes, VCS_ZCODE_DHT_REJECT_IDENTITY),
                (int)BOOT_FRAME_INFRA_NON_ANSWER);
      ASSERT_EQ((int)boot_zcode_dht_frame_classify(
                    no, yes, yes, no, VCS_ZCODE_DHT_REJECT_MALFORMED),
                (int)BOOT_FRAME_INFRA_NON_ANSWER);
      /* Exactly those three guards advanced the counter. */
      ASSERT_EQ(boot_zcode_dht_frame_auth_local_drops(), drops + 3);
      /* With a live, enabled, sessioned service the rejection is
       * evidence: deterministic wire/crypto failure refutes outright;
       * everything else keeps its mapped weight instead. */
      ASSERT_EQ((int)boot_zcode_dht_frame_classify(
                    no, yes, yes, yes, VCS_ZCODE_DHT_REJECT_SIGNATURE),
                (int)BOOT_FRAME_REFUTED);
      ASSERT_EQ((int)boot_zcode_dht_frame_classify(
                    no, yes, yes, yes, VCS_ZCODE_DHT_REJECT_REPLAY),
                (int)BOOT_FRAME_REFUTED);
      ASSERT_EQ((int)boot_zcode_dht_frame_classify(
                    no, yes, yes, yes, VCS_ZCODE_DHT_REJECT_POISONED),
                (int)BOOT_FRAME_REFUTED);
      ASSERT_EQ((int)boot_zcode_dht_frame_classify(
                    no, yes, yes, yes, VCS_ZCODE_DHT_REJECT_IDENTITY),
                (int)BOOT_FRAME_REFUTED);
      ASSERT_EQ((int)boot_zcode_dht_frame_classify(
                    no, yes, yes, yes, VCS_ZCODE_DHT_REJECT_PLAINTEXT),
                (int)BOOT_FRAME_DECODE_DETERMINISTIC);
      ASSERT_EQ((int)boot_zcode_dht_frame_classify(
                    no, yes, yes, yes, VCS_ZCODE_DHT_REJECT_BACKPRESSURE),
                (int)BOOT_FRAME_DECODE_DETERMINISTIC);
    }
    TEST("zcode dht frame auth: backpressure publishes under its own "
         "name without moving any prior position") {
      ASSERT_STR_EQ(vcs_zcode_dht_reject_reason_string(
                        VCS_ZCODE_DHT_REJECT_BACKPRESSURE),
                    "backpressure");
      /* Appended last so previously published keys keep their indices. */
      ASSERT_EQ(VCS_ZCODE_DHT_REJECT_UNAUTHORIZED,
                VCS_ZCODE_DHT_REJECT_BACKPRESSURE - 1);
      /* Every published position names itself; none hits "unknown". */
      for (int i = 0; i < VCS_ZCODE_DHT_REJECT_COUNT; i++)
        ASSERT(strcmp(vcs_zcode_dht_reject_reason_string(
                          (enum vcs_zcode_dht_reject_reason)i),
                      "unknown") != 0);
    }
_test_next:;
  printf("\n=== zcode_dht_frame_auth subset complete: %d failure(s) ===\n",
         failures);
  return failures;
}
