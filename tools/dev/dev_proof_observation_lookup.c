/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded receiver-local projection of signed test observations. */

#include "dev_proof_observation_lookup.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "vcs/vcs_object.h"

#include <stdlib.h>
#include <string.h>

#define OBS_LOG "dev.proof.observation"

static bool nonzero(const uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES])
{
    uint8_t any = 0;
    for (size_t i = 0; i < ZCL_DEV_PROOF_ROOT_BYTES; i++) any |= root[i];
    return any != 0;
}

static bool valid_query(const struct zcl_dev_observation_query *query,
                        size_t domain_count)
{
    return query && query->group && query->group[0] &&
           nonzero(query->key) &&
           query->required_independent_domains != 0 &&
           query->required_independent_domains <= domain_count;
}

static bool valid_domains(const struct zcl_dev_observation_domain *domains,
                          size_t domain_count)
{
    for (size_t i = 0; i < domain_count; i++) {
        if (!nonzero(domains[i].domain_root) ||
            !nonzero(domains[i].producer_pubkey)) return false;
        for (size_t j = 0; j < i; j++) {
            if (memcmp(domains[i].producer_pubkey,
                       domains[j].producer_pubkey,
                       ZCL_DEV_PROOF_PUBKEY_BYTES) == 0 &&
                memcmp(domains[i].domain_root, domains[j].domain_root,
                       ZCL_DEV_PROOF_ROOT_BYTES) != 0)
                return false;
        }
    }
    return true;
}

static bool valid_inputs(const struct zcl_dev_observation_query *query,
                         const struct zcl_dev_observation_object *objects,
                         size_t object_count,
                         const struct zcl_dev_observation_domain *domains,
                         size_t domain_count)
{
    if (object_count > ZCL_DEV_OBSERVATION_MAX_ROOTS ||
        domain_count > ZCL_DEV_OBSERVATION_MAX_DOMAINS ||
        (object_count && !objects) || (domain_count && !domains))
        return false;
    return valid_query(query, domain_count) &&
           valid_domains(domains, domain_count);
}

static bool fresh(const struct zcl_dev_observation_query *query,
                  uint64_t observed_unix)
{
    if (observed_unix > query->now_unix)
        return observed_unix - query->now_unix <= query->max_future_seconds;
    return query->now_unix - observed_unix <= query->max_age_seconds;
}

static int domain_index(const struct zcl_dev_observation_domain *domains,
                        size_t count, const uint8_t pubkey[32])
{
    for (size_t i = 0; i < count; i++) {
        if (memcmp(domains[i].producer_pubkey, pubkey, 32) == 0)
            return (int)i;
    }
    return -1;
}

static uint32_t unique_domains(uint16_t indices,
                               const struct zcl_dev_observation_domain *domains,
                               size_t count)
{
    uint32_t unique = 0;
    for (size_t i = 0; i < count; i++) {
        if ((indices & (uint16_t)(1u << i)) == 0) continue;
        bool prior = false;
        for (size_t j = 0; j < i; j++) {
            if ((indices & (uint16_t)(1u << j)) != 0 &&
                memcmp(domains[i].domain_root, domains[j].domain_root, 32) == 0)
                prior = true;
        }
        if (!prior) unique++;
    }
    return unique;
}

static bool decode_object(const struct zcl_dev_observation_object *object,
                          size_t index, struct zcl_dev_verdict_leaf_v1 *leaf)
{
    if (!object->wire || object->wire_len != ZCL_DEV_VERDICT_LEAF_WIRE_BYTES ||
        !nonzero(object->root)) {
        LOG_ERROR(OBS_LOG, "missing local observation object %zu", index);
        return false;
    }
    uint8_t derived[32];
    char why[96];
    if (!zcl_dev_verdict_leaf_parse(object->wire, object->wire_len,
                                    leaf, why, sizeof(why)) ||
        !zcl_dev_verdict_leaf_root(leaf, derived, why, sizeof(why)) ||
        memcmp(derived, object->root, 32) != 0) {
        LOG_ERROR(OBS_LOG, "local observation object %zu root or wire invalid",
                  index);
        return false;
    }
    return true;
}

static bool seen_root(uint8_t seen[ZCL_DEV_OBSERVATION_MAX_ROOTS][32],
                      size_t *seen_count, const uint8_t root[32])
{
    for (size_t j = 0; j < *seen_count; j++) {
        if (memcmp(seen[j], root, 32) == 0) return true;
    }
    memcpy(seen[(*seen_count)++], root, 32);
    return false;
}

static void account_object(
    const struct zcl_dev_observation_query *query,
    const struct zcl_dev_verdict_leaf_v1 *leaf,
    const struct zcl_dev_observation_domain *domains, size_t domain_count,
    size_t index, uint16_t *pass_domains, uint16_t *fail_domains,
    struct zcl_dev_observation_result_detail *out)
{
    if (memcmp(leaf->key, query->key, sizeof(leaf->key)) != 0 ||
        strcmp(leaf->group, query->group) != 0) return;
    char why[96];
    if (!zcl_dev_verdict_leaf_verify(leaf, query->key, query->group,
                                     why, sizeof(why))) {
        out->invalid_count++;
        return;
    }
    int domain = domain_index(domains, domain_count, leaf->producer_pubkey);
    if (domain < 0) {
        out->invalid_count++;
        return;
    }
    if (!fresh(query, leaf->observed_unix)) {
        out->stale_count++;
        return;
    }
    if (leaf->verdict == ZCL_DEV_VERDICT_LEAF_PASS) {
        out->pass_root_indices[out->pass_count++] = (uint16_t)index;
        *pass_domains |= (uint16_t)(1u << domain);
    } else {
        out->fail_root_indices[out->fail_count++] = (uint16_t)index;
        *fail_domains |= (uint16_t)(1u << domain);
    }
}

static void finish_lookup(const struct zcl_dev_observation_query *query,
                          const struct zcl_dev_observation_domain *domains,
                          size_t domain_count, uint16_t pass_domains,
                          uint16_t fail_domains,
                          struct zcl_dev_observation_result_detail *out)
{
    if (out->pass_count && out->fail_count) {
        out->result = ZCL_DEV_OBSERVATION_CONFLICT;
        return;
    }
    if (!out->pass_count && !out->fail_count) {
        out->result = ZCL_DEV_OBSERVATION_MISS;
        return;
    }
    uint16_t selected = out->pass_count ? pass_domains : fail_domains;
    out->independent_domains = unique_domains(selected, domains, domain_count);
    if (out->independent_domains < query->required_independent_domains) {
        out->result = ZCL_DEV_OBSERVATION_INSUFFICIENT_DOMAINS;
        return;
    }
    out->result = out->pass_count ? ZCL_DEV_OBSERVATION_PASS_EVIDENCE :
                                   ZCL_DEV_OBSERVATION_FAIL_EVIDENCE;
}

void zcl_dev_observation_lookup(
    const struct zcl_dev_observation_query *query,
    const struct zcl_dev_observation_object *objects, size_t object_count,
    bool complete,
    const struct zcl_dev_observation_domain *domains, size_t domain_count,
    struct zcl_dev_observation_result_detail *out)
{
    if (!out) {
        LOG_ERROR(OBS_LOG, "null observation result");
        return;
    }
    memset(out, 0, sizeof(*out));
    out->result = ZCL_DEV_OBSERVATION_UNAVAILABLE;
    if (!complete || !valid_inputs(query, objects, object_count,
                                   domains, domain_count)) {
        LOG_ERROR(OBS_LOG, "incomplete or invalid local observation index");
        return;
    }
    uint8_t seen[ZCL_DEV_OBSERVATION_MAX_ROOTS][32];
    size_t seen_count = 0;
    uint16_t pass_domains = 0, fail_domains = 0;
    for (size_t i = 0; i < object_count; i++) {
        struct zcl_dev_verdict_leaf_v1 leaf;
        if (!decode_object(&objects[i], i, &leaf)) return;
        if (seen_root(seen, &seen_count, objects[i].root)) {
            out->duplicate_roots++;
            continue;
        }
        account_object(query, &leaf, domains, domain_count, i,
                       &pass_domains, &fail_domains, out);
    }
    finish_lookup(query, domains, domain_count, pass_domains,
                  fail_domains, out);
}

void zcl_dev_observation_lookup_local(
    const char *store_root, const struct zcl_dev_observation_query *query,
    const uint8_t (*roots)[ZCL_DEV_PROOF_ROOT_BYTES], size_t root_count,
    bool complete,
    const struct zcl_dev_observation_domain *domains, size_t domain_count,
    struct zcl_dev_observation_result_detail *out)
{
    if (!out) {
        LOG_ERROR(OBS_LOG, "null local observation result");
        return;
    }
    memset(out, 0, sizeof(*out));
    out->result = ZCL_DEV_OBSERVATION_UNAVAILABLE;
    if (!complete || !store_root || !store_root[0] ||
        root_count > ZCL_DEV_OBSERVATION_MAX_ROOTS ||
        (root_count && !roots)) {
        LOG_ERROR(OBS_LOG, "local observation CAS enumeration unavailable");
        return;
    }
    struct zcl_dev_observation_object *objects = zcl_calloc(
        root_count ? root_count : 1u, sizeof(*objects),
        "dev.proof.observation_lookup");
    if (!objects) {
        LOG_ERROR(OBS_LOG, "local observation object allocation failed");
        return;
    }
    bool loaded = true;
    for (size_t i = 0; i < root_count; i++) {
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        if (vcs_object_load_raw_bounded(store_root, roots[i],
                    ZCL_DEV_VERDICT_LEAF_WIRE_BYTES,
                    &wire, &wire_len) != 0) {
            LOG_ERROR(OBS_LOG, "local CAS observation root %zu unavailable", i);
            loaded = false;
            break;
        }
        memcpy(objects[i].root, roots[i], ZCL_DEV_PROOF_ROOT_BYTES);
        objects[i].wire = wire;
        objects[i].wire_len = wire_len;
    }
    if (loaded)
        zcl_dev_observation_lookup(query, objects, root_count, true,
                                   domains, domain_count, out);
    for (size_t i = 0; i < root_count; i++) free((void *)objects[i].wire);
    free(objects);
}
