/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure C23 service-island registry.  Authority and side effects remain in the
 * resident caller; an island receives only caller-owned buffers and values. */

#ifndef ZCL_HOTSWAP_SERVICE_H
#define ZCL_HOTSWAP_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_HOTSWAP_SERVICE_ABI_V1 1u
#define ZCL_HOTSWAP_SERVICE_MAX 16u
#define ZCL_HOTSWAP_SERVICE_SYMBOL "zcl_hotswap_service"

typedef bool (*zcl_hotswap_service_kat_fn)(const void *vtable,
                                            char *why, size_t why_sz);

/* Frozen in the resident executable.  A candidate cannot select its probe or
 * restamp a changed public contract as compatible. */
struct zcl_hotswap_service_contract {
    const char *service_id;
    const char *source_tu;
    uint32_t abi_version;
    size_t vtable_size;
    const char *abi_fingerprint;
    const char *schema_fingerprint;
    const char *wire_fingerprint;
    const char *kat_fingerprint;
    zcl_hotswap_service_kat_fn frozen_kat;
};

/* Exported by a service island.  `vtable` is immutable for the lifetime of
 * the loaded object. */
struct zcl_hotswap_service_candidate {
    const char *service_id;
    const char *source_tu;
    uint32_t abi_version;
    size_t vtable_size;
    const char *abi_fingerprint;
    const char *schema_fingerprint;
    const char *wire_fingerprint;
    const char *kat_fingerprint;
    const void *vtable;
};

/* Emit the one known descriptor symbol only in a service-module build. */
#ifndef ZCL_HOTSWAP_SERVICE_SOURCE_TU
#define ZCL_HOTSWAP_SERVICE_SOURCE_TU __FILE__
#endif
#ifdef ZCL_HOTSWAP_SERVICE_GEN
#define ZCL_HOTSWAP_SERVICE_EXPORT(id_, table_, abi_, schema_, wire_, kat_)  \
    const struct zcl_hotswap_service_candidate zcl_hotswap_service = {      \
        .service_id = (id_),                                                \
        .source_tu = ZCL_HOTSWAP_SERVICE_SOURCE_TU,                         \
        .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,                          \
        .vtable_size = sizeof(table_),                                      \
        .abi_fingerprint = (abi_),                                          \
        .schema_fingerprint = (schema_),                                    \
        .wire_fingerprint = (wire_),                                        \
        .kat_fingerprint = (kat_),                                          \
        .vtable = &(table_),                                                \
    };
#else
#define ZCL_HOTSWAP_SERVICE_EXPORT(id_, table_, abi_, schema_, wire_, kat_)
#endif

struct zcl_hotswap_service_report {
    bool recognized;
    bool ok;
    bool verify_only;
    bool activated;
    bool probed;
    bool rolled_back;
    bool dev_restart;
    uint32_t generation;
    char service_id[96];
    char stage[32];
    char error[256];
};

/* Opaque reader pin.  Call release exactly once after a non-NULL acquire. */
struct zcl_hotswap_service_lease {
    void *snapshot;
};

bool zcl_hotswap_service_publish(
    const struct zcl_hotswap_service_contract *contract,
    const struct zcl_hotswap_service_candidate *candidate,
    bool activate, struct zcl_hotswap_service_report *report);

const void *zcl_hotswap_service_acquire(
    const char *service_id, struct zcl_hotswap_service_lease *lease);
void zcl_hotswap_service_release(struct zcl_hotswap_service_lease *lease);

uint32_t zcl_hotswap_service_generation(void);
bool zcl_hotswap_service_all_retired_quiesced(void);
void zcl_hotswap_service_reset(void);

/* Dev-only loader: confined stock-C shared object -> resident frozen contract
 * -> frozen KAT -> atomic registry publish -> quiescent old-handle retirement.
 * Release builds return a typed unavailable report and never dlopen. */
bool zcl_hotswap_service_activate_so(
    const char *so_path, const char *resolved_datadir, bool request_activate,
    const struct zcl_hotswap_service_contract *contract,
    struct zcl_hotswap_service_report *report);

/* Select exactly one resident-frozen contract by the candidate's immutable
 * service id. Unknown service descriptors are recognized and route to a
 * bounded restart; they never fall through to the command-module ABI. */
bool zcl_hotswap_service_activate_so_any(
    const char *so_path, const char *resolved_datadir, bool request_activate,
    const struct zcl_hotswap_service_contract *const *contracts,
    size_t contract_count, struct zcl_hotswap_service_report *report);

/* Manifest-derived build/classification authority. */
const char *zcl_hotswap_service_source_for_path(const char *path);
const char *zcl_hotswap_service_contract_source_for_path(const char *path);
const char *zcl_hotswap_service_probe_for_source(const char *source);
const char *zcl_hotswap_service_probe_for_id(const char *service_id);
/* Static shell -> pure candidate core. The shell is compile-checked and is
 * never itself loaded into the resident process. */
const char *zcl_hotswap_shadow_service_for_owner(const char *path);
const char *zcl_hotswap_shadow_members_for_service(const char *service);
bool zcl_hotswap_shadow_path_is_static_owner(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_HOTSWAP_SERVICE_H */
