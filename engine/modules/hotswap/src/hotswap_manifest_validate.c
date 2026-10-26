/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Manifest validation for hot-swap generations, split out of
 * hotswap_loader.c. Everything here is pure: it reads only the manifest
 * struct handed to it (plus the host's own build-identity string and the
 * compiled-in runtime-eligible source table) and never touches the
 * generation registry, its lock, or any other loader-owned state. The
 * loader calls hotswap_manifest_v2_validate() after dlopen+dlsym resolve
 * the generation's exported manifest and before any generation code runs;
 * this file is the sole place that decides whether that manifest's
 * schema, host ABI/capability contract, build-source identity, and
 * eligibility/probe pairing are acceptable. */
#include "hotswap/hotswap.h"
#include "hotswap_loader_internal.h"
#include "util/clientversion.h"
#include "util/path_util.h"
#include <stdio.h>
#include <string.h>

static const struct {
    const char *source;
    const char *probe;
} g_eligible_sources[] = {
#define HOTSWAP_ELIGIBLE(path_) { .source = path_, .probe =
#define HOTSWAP_PROBE(probe_) probe_ },
#include "../../../engine/composition/hotswap_eligible.def"
#undef HOTSWAP_PROBE
#undef HOTSWAP_ELIGIBLE
};

static const char *eligible_probe(const char *source_identity)
{
    if (!source_identity || !source_identity[0])
        return NULL;
    for (size_t i = 0;
         i < sizeof(g_eligible_sources) / sizeof(g_eligible_sources[0]); i++) {
        if (strcmp(source_identity, g_eligible_sources[i].source) == 0)
            return g_eligible_sources[i].probe;
    }
    return NULL;
}

bool manifest_text_present(const char *value)
{
    return value && value[0] && strnlen(value, 4096) < 4096;
}

/* Shared rejection for the staged checks below: record the reason in the
 * caller-supplied why buffer (when one was given) and fail the current
 * stage. Every stage takes the same why/why_sz pair that
 * hotswap_manifest_v2_validate() received, so a rejection from any stage
 * reports exactly as a rejection in the old single function did. */
#define MANIFEST_REJECT(...) do {                                            \
        if (why) snprintf(why, why_sz, __VA_ARGS__);                         \
        return false;                                                        \
    } while (0)

/* Stage 1: v2 schema version and struct shape. */
static bool hotswap_manifest_v2_schema_shape_ok(
    const struct zcl_hotswap_manifest_v2 *manifest, char *why, size_t why_sz)
{
    if (manifest->schema_version != ZCL_HOTSWAP_MANIFEST_SCHEMA_V2)
        MANIFEST_REJECT("manifest schema %u != %u", manifest->schema_version,
                        ZCL_HOTSWAP_MANIFEST_SCHEMA_V2);
    if (manifest->struct_size != sizeof(*manifest))
        MANIFEST_REJECT("manifest struct size %u != %zu",
                        manifest->struct_size, sizeof(*manifest));
    return true;
}

/* Stage 2: provider class and the host ABI/capability contract. */
static bool hotswap_manifest_v2_host_contract_ok(
    const struct zcl_hotswap_manifest_v2 *manifest, char *why, size_t why_sz)
{
    /* Native command leaves are the sole provider class. The V4 ABI bump makes
     * every artifact built for a retired host layout fail closed here. */
    if (!manifest_text_present(manifest->provider_id) ||
        strcmp(manifest->provider_id, "native.leaves") != 0) {
        MANIFEST_REJECT("provider is reload-required or unknown: %s",
                        manifest->provider_id ? manifest->provider_id : "");
    }
    if (manifest->host_abi_version != ZCL_HOTSWAP_HOST_ABI_V4 ||
        manifest->host_struct_size != ZCL_HOTSWAP_HOST_STRUCT_SIZE_V4)
        MANIFEST_REJECT("host ABI/size mismatch: abi=%u size=%u",
                        manifest->host_abi_version,
                        manifest->host_struct_size);
    if (manifest->required_host_capabilities !=
        ZCL_HOTSWAP_V4_HOST_CAPABILITIES)
        MANIFEST_REJECT("missing/unsupported host capabilities: 0x%llx",
                        (unsigned long long)
                            manifest->required_host_capabilities);
    return true;
}

/* Stage 3: build-source identity and runtime-eligible source. On success
 * *required_probe is the probe metadata the eligible-source table demands. */
static bool hotswap_manifest_v2_build_source_ok(
    const struct zcl_hotswap_manifest_v2 *manifest,
    const char **required_probe, char *why, size_t why_sz)
{
    const char *host_source_id = zcl_build_source_id_sha256();
    if (!zcl_is_lower_hex(manifest->build_identity, 64) ||
        !zcl_is_lower_hex(host_source_id, 64) ||
        strcmp(manifest->build_identity, host_source_id) != 0)
        MANIFEST_REJECT(
            "build source identity mismatch: generation=%s host=%s",
            manifest->build_identity ? manifest->build_identity : "",
            host_source_id ? host_source_id : "");
    *required_probe = manifest_text_present(manifest->source_identity)
        ? eligible_probe(manifest->source_identity) : NULL;
    if (!*required_probe)
        MANIFEST_REJECT("source is not runtime-eligible: %s",
                        manifest->source_identity ? manifest->source_identity : "");
    return true;
}

/* Stage 4: stateless payload contract - input digest, statelessness,
 * quiescence, mapped test/probe metadata, and the self-test hook. */
static bool hotswap_manifest_v2_payload_contract_ok(
    const struct zcl_hotswap_manifest_v2 *manifest,
    const char *required_probe, char *why, size_t why_sz)
{
    if (!zcl_is_lower_hex(manifest->input_digest, 64))
        MANIFEST_REJECT("input content SHA-256 must be 64 lowercase hex chars");
    if (!manifest->stateless || manifest->state_schema_version != 0)
        MANIFEST_REJECT("stateful provider is reload-required");
    if (manifest->quiescence != ZCL_HOTSWAP_QUIESCENCE_NONE)
        MANIFEST_REJECT("quiescence contract is unsupported in stateless v2");
    if (!manifest_text_present(manifest->mapped_tests_csv) ||
        !manifest_text_present(manifest->probe_tools_csv))
        MANIFEST_REJECT("mapped tests/probe metadata is required");
    if (strcmp(manifest->probe_tools_csv, required_probe) != 0)
        MANIFEST_REJECT("probe metadata mismatch: generation=%s required=%s",
                        manifest->probe_tools_csv, required_probe);
    if (!manifest->self_test)
        MANIFEST_REJECT("generation self-test is required");
    return true;
}

bool hotswap_manifest_v2_validate(
    const struct zcl_hotswap_manifest_v2 *manifest,
    char *why,
    size_t why_sz)
{
    if (why && why_sz)
        why[0] = '\0';
    if (!manifest)
        MANIFEST_REJECT("missing zcl_hotswap_manifest_v2");
    const char *required_probe = NULL;
    return hotswap_manifest_v2_schema_shape_ok(manifest, why, why_sz) &&
           hotswap_manifest_v2_host_contract_ok(manifest, why, why_sz) &&
           hotswap_manifest_v2_build_source_ok(manifest, &required_probe,
                                               why, why_sz) &&
           hotswap_manifest_v2_payload_contract_ok(manifest, required_probe,
                                                   why, why_sz);
}
#undef MANIFEST_REJECT
