/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Bounded, reporter-only reader for the external uptime probe ledger.  This
 * service never controls the node and never turns evidence into authority; it
 * only reports what complete, strict JSONL rows on disk establish. */

#ifndef ZCL_SERVICES_SLO_LEDGER_SUMMARY_H
#define ZCL_SERVICES_SLO_LEDGER_SUMMARY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SLO_LEDGER_TAIL_BYTES       (8u * 1024u * 1024u)
#define SLO_SUMMARY_SAMPLE_CAP      32768u
#define SLO_SUMMARY_INSTANCE_CAP    8u
#define SLO_SUMMARY_INSTANCE_MAX    32u
#define SLO_SUMMARY_DEFAULT_HOURS   24u
#define SLO_SUMMARY_MAX_HOURS       168u
#define SLO_SUMMARY_STALE_SECONDS   180u

struct json_value;

/* Shared command/service validation for bounded ledger instance names. */
bool slo_ledger_instance_valid(const char *instance);

/* Render one explicit ledger path.  `instance` NULL/empty means the required
 * canonical/dev lanes plus every other bounded name actually observed.
 * `now_unix` is explicit so tests never depend on the wall clock. */
bool slo_ledger_summary_render_path(const char *path, const char *instance,
                                    unsigned window_hours, int64_t now_unix,
                                    struct json_value *out);

/* Resolve the production path from ZCL_SLO_LEDGER_DIR (or HOME) and render. */
bool slo_ledger_summary_render(const char *instance, unsigned window_hours,
                               int64_t now_unix, struct json_value *out);

/* dumpstate adapter. key: NULL/empty for all lanes, or one instance name. */
bool slo_evidence_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SERVICES_SLO_LEDGER_SUMMARY_H */
