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
  switch (reason) {
  case VCS_ZCODE_DHT_REJECT_SIGNATURE:
  case VCS_ZCODE_DHT_REJECT_REPLAY:
  case VCS_ZCODE_DHT_REJECT_POISONED:
  case VCS_ZCODE_DHT_REJECT_IDENTITY:
    return PEER_OFFENCE_INVALID_PROOF;
  case VCS_ZCODE_DHT_REJECT_RATE:
  case VCS_ZCODE_DHT_REJECT_CAP:
    return PEER_OFFENCE_FLOOD;
  case VCS_ZCODE_DHT_REJECT_MALFORMED:
  case VCS_ZCODE_DHT_REJECT_SESSION:
    return PEER_OFFENCE_INVALID_MESSAGE;
  case VCS_ZCODE_DHT_REJECT_UNSOLICITED:
    return PEER_OFFENCE_UNREQUESTED;
  case VCS_ZCODE_DHT_REJECT_EXPIRED:
    return PEER_OFFENCE_TIMEOUT;
  /* Delegation stays at payload weight for now: the boolean authorizer
   * cannot separate beacon mismatch (peer guilt) from tip lag or a cold
   * chain cache (infra). Revisit when it grows a cause tri-state. */
  case VCS_ZCODE_DHT_REJECT_DELEGATION:
  case VCS_ZCODE_DHT_REJECT_UNAUTHORIZED:
    return PEER_OFFENCE_INVALID_PAYLOAD;
  case VCS_ZCODE_DHT_REJECT_PLAINTEXT:
  case VCS_ZCODE_DHT_REJECT_BACKPRESSURE:
    return PEER_OFFENCE_NONE;
  case VCS_ZCODE_DHT_REJECT_COUNT:
    break; /* unreachable sentinel: reasons are always below _COUNT */
  }
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
  switch (reason) {
  case VCS_ZCODE_DHT_REJECT_SIGNATURE:
  case VCS_ZCODE_DHT_REJECT_REPLAY:
  case VCS_ZCODE_DHT_REJECT_POISONED:
  case VCS_ZCODE_DHT_REJECT_IDENTITY:
    return BOOT_FRAME_REFUTED;
  /* Deliberately enumerated rather than defaulted: a future reject reason
   * must be classified consciously, not silently scored. */
  case VCS_ZCODE_DHT_REJECT_MALFORMED:
  case VCS_ZCODE_DHT_REJECT_PLAINTEXT:
  case VCS_ZCODE_DHT_REJECT_DELEGATION:
  case VCS_ZCODE_DHT_REJECT_SESSION:
  case VCS_ZCODE_DHT_REJECT_UNSOLICITED:
  case VCS_ZCODE_DHT_REJECT_EXPIRED:
  case VCS_ZCODE_DHT_REJECT_RATE:
  case VCS_ZCODE_DHT_REJECT_CAP:
  case VCS_ZCODE_DHT_REJECT_UNAUTHORIZED:
  case VCS_ZCODE_DHT_REJECT_BACKPRESSURE:
    return BOOT_FRAME_DECODE_DETERMINISTIC;
  case VCS_ZCODE_DHT_REJECT_COUNT:
    break; /* unreachable sentinel: reasons are always below _COUNT */
  }
  return BOOT_FRAME_DECODE_DETERMINISTIC;
}

uint64_t boot_zcode_dht_frame_auth_local_drops(void) {
  return atomic_load_explicit(&g_local_drops, memory_order_relaxed);
}
