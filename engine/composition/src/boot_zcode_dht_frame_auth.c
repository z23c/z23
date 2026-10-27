/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: DHT-frame culpability model — the promoted reject-to-offence
 * table and verdict classifier backing boot_zcode_dht_frame_auth.h. */

#include "config/boot_zcode_dht_frame_auth.h"

#include <stdatomic.h>

static _Atomic uint64_t g_local_drops;

enum peer_offence
boot_zcode_dht_offence(enum vcs_zcode_dht_reject_reason reason) {
  /* Deterministic wire/crypto evidence is decisive: one refuted frame
   * carries the full INVALID_PROOF weight. Rate and quota capacity stay
   * FLOOD; honest session churn (duplicate re-dials) is local retention
   * policy and scores only as a malformed message. PLAINTEXT and
   * BACKPRESSURE are non-answers, never evidence. */
  static const struct {
    enum vcs_zcode_dht_reject_reason reason;
    enum peer_offence offence;
  } k_offence_by_reason[] = {
      {VCS_ZCODE_DHT_REJECT_SIGNATURE, PEER_OFFENCE_INVALID_PROOF},
      {VCS_ZCODE_DHT_REJECT_REPLAY, PEER_OFFENCE_INVALID_PROOF},
      {VCS_ZCODE_DHT_REJECT_POISONED, PEER_OFFENCE_INVALID_PROOF},
      {VCS_ZCODE_DHT_REJECT_IDENTITY, PEER_OFFENCE_INVALID_PROOF},
      {VCS_ZCODE_DHT_REJECT_RATE, PEER_OFFENCE_FLOOD},
      {VCS_ZCODE_DHT_REJECT_CAP, PEER_OFFENCE_FLOOD},
      {VCS_ZCODE_DHT_REJECT_MALFORMED, PEER_OFFENCE_INVALID_MESSAGE},
      {VCS_ZCODE_DHT_REJECT_SESSION, PEER_OFFENCE_INVALID_MESSAGE},
      {VCS_ZCODE_DHT_REJECT_UNSOLICITED, PEER_OFFENCE_UNREQUESTED},
      {VCS_ZCODE_DHT_REJECT_EXPIRED, PEER_OFFENCE_TIMEOUT},
      /* Delegation stays at payload weight for now: the boolean authorizer
       * cannot separate beacon mismatch (peer guilt) from tip lag or a cold
       * chain cache (infra). Revisit when it grows a cause tri-state. */
      {VCS_ZCODE_DHT_REJECT_DELEGATION, PEER_OFFENCE_INVALID_PAYLOAD},
      {VCS_ZCODE_DHT_REJECT_UNAUTHORIZED, PEER_OFFENCE_INVALID_PAYLOAD},
      {VCS_ZCODE_DHT_REJECT_PLAINTEXT, PEER_OFFENCE_NONE},
      {VCS_ZCODE_DHT_REJECT_BACKPRESSURE, PEER_OFFENCE_NONE},
  };
  for (unsigned i = 0;
       i < sizeof k_offence_by_reason / sizeof k_offence_by_reason[0]; ++i) {
    if (k_offence_by_reason[i].reason == reason)
      return k_offence_by_reason[i].offence;
  }
  /* unreachable sentinel: reasons are always below _COUNT */
  return PEER_OFFENCE_NONE;
}

enum boot_zcode_dht_frame_verdict boot_zcode_dht_frame_classify(
    bool handled_ok, bool service_present, bool service_enabled,
    bool have_session, enum vcs_zcode_dht_reject_reason reason) {
  if (handled_ok)
    return BOOT_FRAME_AUTHORIZED;
  /* Guard hardening: a live-but-disabled service cannot meaningfully
   * answer either, so its rejections are local state, not evidence. The
   * two flags are kept separate so callers cannot collapse them into one
   * "truthy pointer" test that scores stale output again. */
  if (!service_present || !service_enabled || !have_session) {
    atomic_fetch_add_explicit(&g_local_drops, 1, memory_order_relaxed);
    return BOOT_FRAME_INFRA_NON_ANSWER;
  }
  static const struct {
    enum vcs_zcode_dht_reject_reason reason;
    enum boot_zcode_dht_frame_verdict verdict;
  } k_verdict_by_reason[] = {
      {VCS_ZCODE_DHT_REJECT_SIGNATURE, BOOT_FRAME_REFUTED},
      {VCS_ZCODE_DHT_REJECT_REPLAY, BOOT_FRAME_REFUTED},
      {VCS_ZCODE_DHT_REJECT_POISONED, BOOT_FRAME_REFUTED},
      {VCS_ZCODE_DHT_REJECT_IDENTITY, BOOT_FRAME_REFUTED},
      /* Deliberately enumerated rather than defaulted: a future reject reason
       * must be classified consciously, not silently scored. */
      {VCS_ZCODE_DHT_REJECT_MALFORMED, BOOT_FRAME_DECODE_DETERMINISTIC},
      {VCS_ZCODE_DHT_REJECT_PLAINTEXT, BOOT_FRAME_DECODE_DETERMINISTIC},
      {VCS_ZCODE_DHT_REJECT_DELEGATION, BOOT_FRAME_DECODE_DETERMINISTIC},
      {VCS_ZCODE_DHT_REJECT_SESSION, BOOT_FRAME_DECODE_DETERMINISTIC},
      {VCS_ZCODE_DHT_REJECT_UNSOLICITED, BOOT_FRAME_DECODE_DETERMINISTIC},
      {VCS_ZCODE_DHT_REJECT_EXPIRED, BOOT_FRAME_DECODE_DETERMINISTIC},
      {VCS_ZCODE_DHT_REJECT_RATE, BOOT_FRAME_DECODE_DETERMINISTIC},
      {VCS_ZCODE_DHT_REJECT_CAP, BOOT_FRAME_DECODE_DETERMINISTIC},
      {VCS_ZCODE_DHT_REJECT_UNAUTHORIZED, BOOT_FRAME_DECODE_DETERMINISTIC},
      {VCS_ZCODE_DHT_REJECT_BACKPRESSURE, BOOT_FRAME_DECODE_DETERMINISTIC},
  };
  /* Keeps the original exhaustive-switch guarantee: adding a reject reason
   * without a row here fails the build instead of being silently scored. */
  static_assert(sizeof k_verdict_by_reason / sizeof k_verdict_by_reason[0] ==
                    VCS_ZCODE_DHT_REJECT_COUNT,
                "classify every vcs_zcode_dht_reject_reason explicitly");
  for (unsigned i = 0;
       i < sizeof k_verdict_by_reason / sizeof k_verdict_by_reason[0]; ++i) {
    if (k_verdict_by_reason[i].reason == reason)
      return k_verdict_by_reason[i].verdict;
  }
  /* unreachable sentinel: reasons are always below _COUNT */
  return BOOT_FRAME_DECODE_DETERMINISTIC;
}

uint64_t boot_zcode_dht_frame_auth_local_drops(void) {
  return atomic_load_explicit(&g_local_drops, memory_order_relaxed);
}
