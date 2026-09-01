/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The telemetry PROVIDER registry: domain name -> the collector that fills
 * that domain's typed snapshot.
 *
 * WHY THIS EXISTS. util/telemetry_render.h already registers every domain's
 * SCHEMA (what the fields are) and can iterate it. It deliberately does not
 * know how to OBTAIN a snapshot, because a collector reads node services and
 * lives in app/services, above platform/modules/util. Without this file a rollup that wants
 * "the health of every domain" has to name all eight collectors by hand, and
 * the ninth domain silently does not appear in it — the exact half-registered
 * shape telemetry_domains.def exists to forbid.
 *
 * HOW OMISSION IS MADE IMPOSSIBLE. The table below is pasted from
 * util/telemetry_domains.def, the same file the schemas come from, so the
 * provider table and the schema table cannot hold different domain sets. Each
 * row names an adapter `tp_fill_<domain>` that the .def forward-declares and
 * telemetry_providers.c must define; a domain added to the .def and nowhere
 * else fails to link against an adapter that was never written. Registration
 * is therefore a compile-time property, not a convention.
 *
 * WHY ADAPTERS AND NOT THE COLLECTORS DIRECTLY. Two collectors do not have the
 * contract signature: runtime_dump_state_fill() takes a `const char **why`
 * out-parameter and agents_dump_state_fill() returns void. Casting a function
 * pointer to a different signature and calling through it is undefined
 * behaviour, so each domain gets a three-line adapter with the uniform shape
 * instead. The divergence is absorbed in one visible place rather than being
 * hidden behind a cast.
 *
 * A collector that reports failure is NOT an error for the caller to abort on:
 * it means that one domain could not be read, which is a fact about the node
 * worth reporting. Rollups render such a domain as health `unknown` with a
 * reason, never dropping it from the list.
 */
#ifndef ZCL_SERVICES_TELEMETRY_PROVIDERS_H
#define ZCL_SERVICES_TELEMETRY_PROVIDERS_H

#include <stdbool.h>
#include <stddef.h>

struct telemetry_domain_schema;

/* One domain's collector, in the uniform shape rollups can call blind. */
struct telemetry_provider {
    const char *domain; /* equals the schema's `domain` and the ontology
                         * subsystem name */
    bool (*fill)(void *snapshot); /* snapshot is `struct <domain>_snapshot *`,
                                   * zero-initialized by the caller */
    size_t snapshot_size;
    const struct telemetry_domain_schema *schema;
};

size_t telemetry_provider_count(void);
const struct telemetry_provider *telemetry_provider_at(size_t idx);
const struct telemetry_provider *telemetry_provider_find(const char *domain);

/* Largest `struct <domain>_snapshot` in the registry. A caller that wants one
 * buffer it can reuse across every domain sizes it with this rather than
 * guessing or allocating per domain. */
size_t telemetry_snapshot_max_size(void);

/* Zero `buf`, then run `p`'s collector over it. Returns false if the buffer is
 * too small for that domain (never a partial fill) or the collector refused.
 * The zeroing is load-bearing: zero is TELEMETRY_UNSET, the provider-defect
 * presence the render layer counts, so a field the collector forgets is
 * reported rather than read as a plausible 0. */
bool telemetry_provider_collect(const struct telemetry_provider *p, void *buf,
                                size_t buf_sz);

#endif /* ZCL_SERVICES_TELEMETRY_PROVIDERS_H */
