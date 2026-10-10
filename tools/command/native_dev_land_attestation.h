/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: bound landing self-observation and launcher-capture consistency contracts. */
#ifndef ZCL_DEV_LAND_ATTESTATION_H
#define ZCL_DEV_LAND_ATTESTATION_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define ZCL_LAND_ATTEST_CAP 2048u
#define ZCL_LAND_ATTEST_SCHEMA "zcl.dev_land.self_attestation.v1"
/* Diagnostic same-call intervals only; absent records mean unknown. Not signed
 * acceptance evidence. Refusal clears out when out and capacity are supplied. */
struct zcl_land_beat {
    const char *beat, *base, *local, *tree;
    long long seq, attempt;
    int64_t started_us, finished_us;
};
bool zcl_dev_land_beat_format(const struct zcl_land_beat *b, char *out, size_t cap);
/* Pure phase-row digest, never 0; NULL fields read as empty; only the digits after "proof_request_idle_age_s=" in detail are ignored. */
long long zcl_dev_land_phase_digest(const char *state, const char *phase,
    long long attempt, const char *dimension, const char *note,
    const char *detail, const char *log_base, const char *tip);
/* Self-observation only. UNKNOWN service origin never grants timer authority.
 * Decoder requires independently expected image/source and a bounded age. */
bool zcl_dev_land_attestation_decode(const char *wire, size_t length,
    const char *image, const char *source, int64_t now, bool *fixture_enabled);
/* V1 normalized public captures. Strings are borrowed NUL-terminated values;
 * an adapter must reject duplicate/array fields, truncation and collector errors.
 * This pure check establishes consistency, never authenticates supplied data. */
struct zcl_land_launcher_identity {
    const char *unit, *descriptor_sha256, *invocation_id, *boot_id;
    uint32_t manager_uid, pid;
    int64_t captured_at_ms;
};
struct zcl_land_launcher_frame {
    struct zcl_land_launcher_identity identity;
    uint32_t uid;
    const char *transport, *cursor, *wire;
    size_t length;
    int64_t journal_at_ms;
};
struct zcl_land_launcher_capture {
    struct zcl_land_launcher_identity before, after;
    const struct zcl_land_launcher_frame *frames;
    size_t frame_count;
    bool complete;
};
/* False means UNKNOWN; true is only MATCHED_CAPTURE, not runtime authority.
 * expected identities come from receiver review, not the journal MESSAGE. */
bool zcl_dev_land_launcher_join(
    const struct zcl_land_launcher_identity *expected,
    const struct zcl_land_launcher_capture *capture, int64_t now,
    bool *fixture_enabled);
#endif
