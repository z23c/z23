/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * soak_attestation_service — persistent evidence log for the 7-day soak
 * criterion (MVP criterion 7).
 *
 * Every tick (60 s) the service appends one JSON line to
 * <datadir>/soak_attestation.jsonl:
 *   {"ts":<unix>,"height":<N>,"healthy":<bool>,
 *    "degraded_reason":"<string-or-empty>",
 *    "security_review_required":<bool>,"security_posture_ok":<bool>,
 *    "window_eligible":<bool>,
 *    "source_id_sha256":"<sha256>","build_commit":"<git-trace>",
 *    "uptime_s":<N>}
 *
 * The line log is bounded (rotate at 50 MB to a single .1 suffix) and
 * fsynced every 10 lines so a crash-only-safe OS event is never lost.
 *
 * LOCK-ORDER LAW: this service runs on its own supervised health-ring tick,
 * NEVER on the reducer drive. node_health_collect() is safe to call from any
 * non-drive thread (it takes csr->lock THEN coins_kv, which is the established
 * order on the health/RPC path). */

#ifndef ZCL_SOAK_ATTESTATION_SERVICE_H
#define ZCL_SOAK_ATTESTATION_SERVICE_H

#include <stdbool.h>
#include <stdint.h>

struct json_value;

/* Maximum file size before rotation (50 MB). */
#define SOAK_ATTESTATION_ROTATE_BYTES  (50 * 1024 * 1024)

/* fsync every N lines. */
#define SOAK_ATTESTATION_FSYNC_EVERY    10

/* Init: arm the service with the process datadir. Idempotent.
 * Must be called before the first tick; can pass NULL to disable (no-op). */
void soak_attestation_init(const char *datadir);

/* Tick body — appends one line and rotates/fsyncs as needed.
 * Safe to call from any non-reducer-drive thread. */
void soak_attestation_tick(void);

/* State dump (see CLAUDE.md "Adding state introspection"). */
bool soak_dump_state_json(struct json_value *out, const char *key);

/* Reset global state for tests only. */
void soak_attestation_reset_for_test(void);

#endif /* ZCL_SOAK_ATTESTATION_SERVICE_H */
