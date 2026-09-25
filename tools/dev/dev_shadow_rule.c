/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The checked parts of shadow selection: names, the fallback
 * classifier, the compositional reuse rule and the path predicates. */

#include "dev_shadow_select.h"

#include "crypto/ed25519.h"
#include "platform/clock.h"
#include "sha3/sha3.h"

#include <string.h>

static const char *const shadow_kind_names[ZCL_SHADOW_KIND__COUNT] = {
    "real", "header_decl", "abi", "flag", "contract", "private_impl",
    "generated_input", "negative_lookup", "macro",
};

const char *zcl_shadow_kind_name(enum zcl_shadow_kind kind)
{
    if ((unsigned)kind >= ZCL_SHADOW_KIND__COUNT) return "unknown";
    return shadow_kind_names[kind];
}

bool zcl_shadow_kind_parse(const char *text, enum zcl_shadow_kind *out)
{
    if (!text || !out) return false;
    for (unsigned i = 0; i < ZCL_SHADOW_KIND__COUNT; i++) {
        if (strcmp(text, shadow_kind_names[i]) == 0) {
            *out = (enum zcl_shadow_kind)i;
            return true;
        }
    }
    return false;
}

const char *zcl_shadow_fallback_name(enum zcl_shadow_fallback reason)
{
    switch (reason) {
    case ZCL_SHADOW_FALLBACK_NONE: return "none";
    case ZCL_SHADOW_FALLBACK_UNKNOWN_SCOPE: return "unknown-scope";
    case ZCL_SHADOW_FALLBACK_POLICY: return "policy";
    case ZCL_SHADOW_FALLBACK_CONFLICT: return "conflict";
    case ZCL_SHADOW_FALLBACK_DEPENDENCY_CHANGE: return "dependency-change";
    case ZCL_SHADOW_FALLBACK__COUNT: break;
    }
    return "unknown";
}

const char *
zcl_shadow_contract_change_name(enum zcl_shadow_contract_change change)
{
    switch (change) {
    case ZCL_SHADOW_CONTRACT_NONE: return "none";
    case ZCL_SHADOW_CONTRACT_ADDITIVE: return "additive";
    case ZCL_SHADOW_CONTRACT_MOVED: return "moved";
    }
    return "unknown";
}

/* Precedence is fixed: evidence that contradicts itself outranks policy,
 * policy outranks a moved build graph, and a moved build graph outranks a
 * scope the selector could not name. The first true fact decides. */
enum zcl_shadow_fallback
zcl_shadow_classify(const struct zcl_shadow_scope_facts *facts)
{
    if (!facts || facts->bytes_mismatch || facts->plan_refused)
        return ZCL_SHADOW_FALLBACK_CONFLICT;
    if (facts->consensus_policy) return ZCL_SHADOW_FALLBACK_POLICY;
    if (facts->build_graph_input || facts->generated_input)
        return ZCL_SHADOW_FALLBACK_DEPENDENCY_CHANGE;
    if (facts->negative_lookup || facts->closure_universal)
        return ZCL_SHADOW_FALLBACK_UNKNOWN_SCOPE;
    return ZCL_SHADOW_FALLBACK_NONE;
}

const char *zcl_shadow_reuse_name(enum zcl_shadow_reuse decision)
{
    switch (decision) {
    case ZCL_SHADOW_REUSE_ADMIT: return "admit";
    case ZCL_SHADOW_REUSE_REFUSE_MALFORMED: return "malformed_claim";
    case ZCL_SHADOW_REUSE_REFUSE_CONTRACT_CHANGED: return "contract_changed";
    case ZCL_SHADOW_REUSE_REFUSE_CONTRACT_NOT_EXECUTED:
        return "contract_not_freshly_executed";
    case ZCL_SHADOW_REUSE_REFUSE_CONTRACT_FAILED: return "contract_failed";
    case ZCL_SHADOW_REUSE_REFUSE_CONTRACT_STALE_IMPL:
        return "contract_ran_on_other_implementation";
    case ZCL_SHADOW_REUSE_REFUSE_PRIVATE_PREMISE:
        return "caller_premise_not_contract";
    }
    return "unknown";
}

static bool shadow_root_zero(const uint8_t root[ZCL_SHADOW_ROOT_BYTES])
{
    uint8_t acc = 0;
    for (size_t i = 0; i < ZCL_SHADOW_ROOT_BYTES; i++) acc |= root[i];
    return acc == 0;
}

static bool shadow_claim_well_formed(const struct zcl_shadow_reuse_claim *c)
{
    if (!c) return false;
    if (c->caller_premise_count > 0 && !c->caller_premises) return false;
    return !shadow_root_zero(c->contract_before) &&
           !shadow_root_zero(c->contract_after) &&
           !shadow_root_zero(c->callee_impl_after);
}

/* Condition 2: an EXECUTED PASS of at least one contract obligation on the
 * exact new implementation. A reused PASS is provenance, and a PASS on any
 * other implementation root is an old PASS. */
static enum zcl_shadow_reuse
shadow_contract_run(const struct zcl_shadow_reuse_claim *c)
{
    if (c->contract_basis != ZCL_SHADOW_BASIS_EXECUTED ||
        c->contract_verdict == ZCL_SHADOW_VERDICT_NOT_RUN ||
        c->contract_obligations == 0)
        return ZCL_SHADOW_REUSE_REFUSE_CONTRACT_NOT_EXECUTED;
    if (c->contract_verdict != ZCL_SHADOW_VERDICT_PASS)
        return ZCL_SHADOW_REUSE_REFUSE_CONTRACT_FAILED;
    if (memcmp(c->contract_run_impl, c->callee_impl_after,
               ZCL_SHADOW_ROOT_BYTES) != 0)
        return ZCL_SHADOW_REUSE_REFUSE_CONTRACT_STALE_IMPL;
    return ZCL_SHADOW_REUSE_ADMIT;
}

/* Condition 3: every caller premise names the contract. An empty premise set
 * is refused too: a caller that states no premise has not shown that it
 * reaches the callee only through the contract. */
static bool shadow_premises_contract_only(const struct zcl_shadow_reuse_claim *c)
{
    if (c->caller_premise_count == 0) return false;
    for (size_t i = 0; i < c->caller_premise_count; i++)
        if (c->caller_premises[i] != ZCL_SHADOW_PREMISE_CONTRACT)
            return false;
    return true;
}

enum zcl_shadow_reuse
zcl_shadow_reuse_admit(const struct zcl_shadow_reuse_claim *claim)
{
    if (!shadow_claim_well_formed(claim))
        return ZCL_SHADOW_REUSE_REFUSE_MALFORMED;
    if (memcmp(claim->contract_before, claim->contract_after,
               ZCL_SHADOW_ROOT_BYTES) != 0)
        return ZCL_SHADOW_REUSE_REFUSE_CONTRACT_CHANGED;
    enum zcl_shadow_reuse run = shadow_contract_run(claim);
    if (run != ZCL_SHADOW_REUSE_ADMIT) return run;
    if (!shadow_premises_contract_only(claim))
        return ZCL_SHADOW_REUSE_REFUSE_PRIVATE_PREMISE;
    return ZCL_SHADOW_REUSE_ADMIT;
}

static const char *const shadow_field_names[ZCL_SHADOW_FIELD__COUNT] = {
    "source_closure", "dependency_closure", "negative_lookups",
    "generated_inputs", "flags", "abi_generation", "build_graph", "harness",
    "fixtures", "invariants", "integration_edges", "unit_id",
};

const char *zcl_shadow_field_name(enum zcl_shadow_field field)
{
    if ((unsigned)field >= ZCL_SHADOW_FIELD__COUNT) return "unknown";
    return shadow_field_names[field];
}

/* zcl.zcode.component_input_key.v1 binds the candidate source TREE root, the
 * dependency lock, the accepted test recipe, the payload, and an execution
 * closure of toolchain, compiler, flags, environment, build graph, harness,
 * proof and sandbox policies and limits. It has no per-obligation unit, no
 * per-obligation dependency (callee implementation) closure, no lookup
 * misses, no generator provenance, no ABI generation, no fixture root apart
 * from the recipe, no declared invariants and no callee contract edges. */
uint32_t zcl_shadow_component_input_key_gaps(void)
{
    return (1u << ZCL_SHADOW_FIELD_UNIT_ID) |
           (1u << ZCL_SHADOW_FIELD_DEPENDENCY_CLOSURE) |
           (1u << ZCL_SHADOW_FIELD_NEGATIVE_LOOKUPS) |
           (1u << ZCL_SHADOW_FIELD_GENERATED_INPUTS) |
           (1u << ZCL_SHADOW_FIELD_ABI_GENERATION) |
           (1u << ZCL_SHADOW_FIELD_FIXTURES) |
           (1u << ZCL_SHADOW_FIELD_INVARIANTS) |
           (1u << ZCL_SHADOW_FIELD_INTEGRATION_EDGES);
}

static bool shadow_has_prefix(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static bool shadow_has_suffix(const char *s, const char *suffix)
{
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && strcmp(s + n - m, suffix) == 0;
}

/* The contract surface of a component: its public headers, its own module
 * tests, and the registered harness group(s) that prove it. A harness test
 * belongs to a component when its stem names the component's leaf
 * directory (platform/modules/codec -> test_codec*.c). */
bool zcl_shadow_path_is_contract(const char *component, const char *path)
{
    if (!component || !path || !component[0]) return false;
    size_t clen = strlen(component);
    if (strncmp(path, component, clen) == 0 && path[clen] == '/') {
        const char *rest = path + clen + 1;
        if (shadow_has_prefix(rest, "include/") &&
            shadow_has_suffix(rest, ".h"))
            return true;
        return shadow_has_prefix(rest, "tests/");
    }
    const char *leaf = strrchr(component, '/');
    leaf = leaf ? leaf + 1 : component;
    char stem[ZCL_SHADOW_PATH_MAX];
    int n = snprintf(stem, sizeof(stem), "tests/harness/src/test_%s", leaf);
    if (n <= 0 || (size_t)n >= sizeof(stem)) return false;
    return shadow_has_prefix(path, stem) && shadow_has_suffix(path, ".c");
}

/* Mirrors the Makefile's VIEW_GEN_HEADERS producers (TMPL_SRC, SITE_CSS_SRC,
 * INSTALL_SH_SRC). A new generator must be added here or its inputs will be
 * classified as ordinary files; the test group pins the current set. */
bool zcl_shadow_path_is_generator_input(const char *path)
{
    if (!path) return false;
    if (shadow_has_prefix(path, "contexts/explorer/views/templates/") &&
        shadow_has_suffix(path, ".chtml"))
        return true;
    if (shadow_has_prefix(path, "contexts/wallet/views/css/") &&
        shadow_has_suffix(path, ".ccss"))
        return true;
    return strcmp(path, "contexts/explorer/views/src/site.css") == 0 ||
           strcmp(path, "platform/packaging/install/install_from_source.sh") ==
               0;
}

bool zcl_shadow_path_is_build_graph(const char *path)
{
    if (!path) return false;
    return strcmp(path, "Makefile") == 0 || shadow_has_suffix(path, ".mk");
}

/* RFC 8032 section 7.1 TEST 1: empty message. */
static const uint8_t shadow_rfc8032_pk[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe,
    0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6,
    0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};
static const uint8_t shadow_rfc8032_sig[64] = {
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2,
    0xcc, 0x80, 0x6e, 0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5,
    0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55, 0x5f,
    0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70,
    0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe,
    0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
};

/* One obligation's validation: 19 field roots, the 624-byte key preimage,
 * the 360-byte ticket root, and one signature verify. */
static bool shadow_validate_once(uint8_t scratch[624])
{
    uint8_t root[32];
    for (unsigned f = 0; f < 19u; f++) {
        zcl_sha3_256(scratch + f * 32u, 32, root);
        memcpy(scratch + 16u + f * 32u, root, sizeof(root));
    }
    zcl_sha3_256(scratch, 624, root);
    zcl_sha3_256(scratch, 360, root);
    scratch[0] ^= root[0];
    static const uint8_t empty[1] = {0};
    return ed25519_verify(shadow_rfc8032_sig, empty, 0, shadow_rfc8032_pk);
}

uint64_t zcl_shadow_validation_ns_per_obligation(void)
{
    enum { ROUNDS = 64 };
    uint8_t scratch[624];
    memset(scratch, 0x5a, sizeof(scratch));
    int64_t start = clock_now_monotonic_ns();
    unsigned ok = 0;
    for (unsigned i = 0; i < ROUNDS; i++)
        ok += shadow_validate_once(scratch) ? 1u : 0u;
    int64_t elapsed = clock_now_monotonic_ns() - start;
    if (ok != ROUNDS || elapsed <= 0) return 0;
    return (uint64_t)elapsed / ROUNDS;
}
