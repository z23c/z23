/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Bounded, read-only observation of a co-located legacy zclassicd wallet. */

#ifndef ZCL_SERVICES_LEGACY_BALANCE_OBSERVER_H
#define ZCL_SERVICES_LEGACY_BALANCE_OBSERVER_H

#include "base/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LEGACY_BALANCE_OBSERVER_TIMEOUT_MS 250u
#define LEGACY_BALANCE_OBSERVER_REASON_MAX 160u

enum legacy_balance_source {
    LEGACY_BALANCE_SOURCE_ZCLASSICD = 1,
};

struct legacy_balance_observation {
    enum legacy_balance_source source;
    bool complete;
    int64_t transparent_zat;
    int64_t shielded_zat;
    int64_t total_zat;
    int64_t observed_at_unix;
    char reason[LEGACY_BALANCE_OBSERVER_REASON_MAX + 1u];
};

typedef bool (*legacy_balance_rpc_call_fn)(
    const char *body_json, uint32_t timeout_ms, char **out_resp,
    char *err, size_t err_sz);

/* Parse the exact decimal-string shape returned by z_gettotalbalance. */
struct zcl_result legacy_balance_observation_parse(
    const char *raw_response, struct legacy_balance_observation *out);

/* Testable transport seam. The timeout is constrained to 1..250 ms. */
struct zcl_result legacy_balance_observe_with_call(
    legacy_balance_rpc_call_fn call, uint32_t timeout_ms,
    struct legacy_balance_observation *out);

/* Query ~/.zclassic's authenticated local zclassicd without mutating it. */
struct zcl_result legacy_balance_observe(
    struct legacy_balance_observation *out);

#ifdef ZCL_TESTING
/* Process-local hermetic seam; tests must restore NULL before returning. */
void legacy_balance_observer_set_test_call(legacy_balance_rpc_call_fn call);
#endif

#endif
