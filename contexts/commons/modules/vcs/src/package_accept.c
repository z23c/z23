/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_accept — implementation. See vcs/package_accept.h. */

#include "vcs/package_accept.h"

#include "chain/chainparams.h"
#include "keys/key_io.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct accept_pub_record {
    uint8_t pubkey[VCS_PACKAGE_RELEASE_PUBKEY_BYTES];
    uint64_t sequence;
    uint8_t release_id[32];
};

struct accept_ns_record {
    char publisher[VCS_PACKAGE_RELEASE_NAME_HALF_MAX + 1u];
    uint8_t pubkey[VCS_PACKAGE_RELEASE_PUBKEY_BYTES];
};

struct vcs_package_accept {
    struct accept_pub_record *pubs;
    size_t pubs_count;
    size_t pubs_cap;
    struct accept_ns_record *namespaces;
    size_t ns_count;
    size_t ns_cap;
};

const char *vcs_package_accept_result_string(
    enum vcs_package_accept_result result)
{
    switch (result) {
    case VCS_PACKAGE_ACCEPT_OK: return "accepted";
    case VCS_PACKAGE_ACCEPT_DUPLICATE: return "duplicate-release";
    case VCS_PACKAGE_ACCEPT_EQUIVOCATION: return "publisher-equivocation";
    case VCS_PACKAGE_ACCEPT_STALE: return "stale-publisher-sequence";
    case VCS_PACKAGE_ACCEPT_CHAIN_ID: return "wrong-chain-id";
    case VCS_PACKAGE_ACCEPT_REWARD: return "invalid-reward-address";
    case VCS_PACKAGE_ACCEPT_NAMESPACE: return "publisher-namespace-conflict";
    case VCS_PACKAGE_ACCEPT_INVALID: return "envelope-invalid";
    case VCS_PACKAGE_ACCEPT_ERR_NULL: return "null-argument";
    case VCS_PACKAGE_ACCEPT_ERR_ALLOC: return "allocation-failed";
    case VCS_PACKAGE_ACCEPT_ERR_LIMIT: return "state-limit";
    }
    return "unknown-result";
}

bool vcs_package_accept_chain_id(char *out, size_t out_capacity)
{
    if (!out)
        return false;
    const struct chain_params *params = chain_params_get();
    if (!params)
        return false;
    int n = snprintf(out, out_capacity, "zclassic-%s", params->strNetworkID);
    return n > 0 && (size_t)n < out_capacity &&
           (size_t)n <= VCS_PACKAGE_RELEASE_CHAIN_ID_MAX;
}

struct vcs_package_accept *vcs_package_accept_new(void)
{
    struct vcs_package_accept *accept =
        zcl_malloc(sizeof(*accept), "vcs_package_accept");
    if (!accept)
        LOG_NULL("vcs.accept", "alloc package accept");
    accept->pubs = NULL;
    accept->pubs_count = 0;
    accept->pubs_cap = 0;
    accept->namespaces = NULL;
    accept->ns_count = 0;
    accept->ns_cap = 0;
    return accept;
}

struct vcs_package_accept *vcs_package_accept_clone(
    const struct vcs_package_accept *accept)
{
    if (!accept)
        LOG_NULL("vcs.accept", "clone null acceptance context");
    struct vcs_package_accept *copy = vcs_package_accept_new();
    if (!copy)
        return NULL;
    if (accept->pubs_count) {
        copy->pubs = zcl_malloc(accept->pubs_count * sizeof(*copy->pubs),
                                "vcs_accept_clone_pubs");
        if (!copy->pubs) {
            vcs_package_accept_free(copy);
            LOG_NULL("vcs.accept", "clone publisher cursors");
        }
        memcpy(copy->pubs, accept->pubs,
               accept->pubs_count * sizeof(*copy->pubs));
        copy->pubs_count = copy->pubs_cap = accept->pubs_count;
    }
    if (accept->ns_count) {
        copy->namespaces = zcl_malloc(
            accept->ns_count * sizeof(*copy->namespaces),
            "vcs_accept_clone_namespaces");
        if (!copy->namespaces) {
            vcs_package_accept_free(copy);
            LOG_NULL("vcs.accept", "clone namespace bindings");
        }
        memcpy(copy->namespaces, accept->namespaces,
               accept->ns_count * sizeof(*copy->namespaces));
        copy->ns_count = copy->ns_cap = accept->ns_count;
    }
    return copy;
}

void vcs_package_accept_free(struct vcs_package_accept *accept)
{
    if (!accept)
        return;
    free(accept->pubs);
    free(accept->namespaces);
    free(accept);
}

static struct accept_pub_record *accept_pub_find(
    struct vcs_package_accept *accept, const uint8_t pubkey[33])
{
    for (size_t i = 0; i < accept->pubs_count; i++)
        if (memcmp(accept->pubs[i].pubkey, pubkey,
                   VCS_PACKAGE_RELEASE_PUBKEY_BYTES) == 0)
            return &accept->pubs[i];
    return NULL;
}

static const struct accept_ns_record *accept_ns_find(
    const struct vcs_package_accept *accept, const char *publisher)
{
    for (size_t i = 0; i < accept->ns_count; i++)
        if (strcmp(accept->namespaces[i].publisher, publisher) == 0)
            return &accept->namespaces[i];
    return NULL;
}

static bool accept_pub_record(struct vcs_package_accept *accept,
                              const uint8_t pubkey[33], uint64_t sequence,
                              const uint8_t release_id[32])
{
    struct accept_pub_record *record = accept_pub_find(accept, pubkey);
    if (record) {
        record->sequence = sequence;
        memcpy(record->release_id, release_id, 32);
        return true;
    }
    if (accept->pubs_count >= VCS_PACKAGE_ACCEPT_MAX_PUBLISHERS)
        LOG_FAIL("vcs.accept", "publisher limit reached");
    if (accept->pubs_count == accept->pubs_cap) {
        size_t cap = accept->pubs_cap ? accept->pubs_cap * 2 : 16;
        if (cap > VCS_PACKAGE_ACCEPT_MAX_PUBLISHERS)
            cap = VCS_PACKAGE_ACCEPT_MAX_PUBLISHERS;
        struct accept_pub_record *pubs = zcl_realloc(
            accept->pubs, cap * sizeof(*pubs), "vcs_accept_pubs");
        if (!pubs)
            LOG_FAIL("vcs.accept", "grow publisher table");
        accept->pubs = pubs;
        accept->pubs_cap = cap;
    }
    struct accept_pub_record *fresh = &accept->pubs[accept->pubs_count++];
    memcpy(fresh->pubkey, pubkey, VCS_PACKAGE_RELEASE_PUBKEY_BYTES);
    fresh->sequence = sequence;
    memcpy(fresh->release_id, release_id, 32);
    return true;
}

static bool accept_ns_bind(struct vcs_package_accept *accept,
                           const char *publisher, const uint8_t pubkey[33])
{
    if (accept->ns_count >= VCS_PACKAGE_ACCEPT_MAX_NAMESPACES)
        LOG_FAIL("vcs.accept", "namespace limit reached");
    if (accept->ns_count == accept->ns_cap) {
        size_t cap = accept->ns_cap ? accept->ns_cap * 2 : 16;
        if (cap > VCS_PACKAGE_ACCEPT_MAX_NAMESPACES)
            cap = VCS_PACKAGE_ACCEPT_MAX_NAMESPACES;
        struct accept_ns_record *namespaces = zcl_realloc(
            accept->namespaces, cap * sizeof(*namespaces),
            "vcs_accept_namespaces");
        if (!namespaces)
            LOG_FAIL("vcs.accept", "grow namespace table");
        accept->namespaces = namespaces;
        accept->ns_cap = cap;
    }
    struct accept_ns_record *fresh =
        &accept->namespaces[accept->ns_count++];
    snprintf(fresh->publisher, sizeof(fresh->publisher), "%s", publisher);
    memcpy(fresh->pubkey, pubkey, VCS_PACKAGE_RELEASE_PUBKEY_BYTES);
    return true;
}

/* The reward address, when present, must decode as a transparent address
 * (t1 P2PKH / t3 P2SH) of the ACTIVE chain. */
static bool accept_reward_valid(const char *reward)
{
    if (!reward[0])
        return true; /* empty = no reward address */
    const struct chain_params *params = chain_params_get();
    if (!params)
        return false;
    size_t pubkey_len = 0;
    size_t script_len = 0;
    const unsigned char *pubkey_prefix =
        chain_params_base58_prefix(params, B58_PUBKEY_ADDRESS, &pubkey_len);
    const unsigned char *script_prefix =
        chain_params_base58_prefix(params, B58_SCRIPT_ADDRESS, &script_len);
    struct tx_destination dest;
    return decode_destination(reward, pubkey_prefix, pubkey_len,
                              script_prefix, script_len, &dest);
}

static enum vcs_package_accept_result accept_verified_release_id(
    const struct vcs_package_release *release,
    uint8_t release_id[VCS_PACKAGE_RELEASE_ID_BYTES])
{
    if (vcs_package_release_verify(release) != VCS_PACKAGE_RELEASE_OK)
        return VCS_PACKAGE_ACCEPT_INVALID;
    if (vcs_package_release_id(release, release_id) !=
        VCS_PACKAGE_RELEASE_OK)
        return VCS_PACKAGE_ACCEPT_INVALID;
    return VCS_PACKAGE_ACCEPT_OK;
}

static enum vcs_package_accept_result accept_publisher_namespace(
    const struct vcs_package_accept *accept,
    const struct vcs_package_release *release,
    char *publisher, size_t publisher_size,
    const struct accept_ns_record **ns_out)
{
    const char *slash = strchr(release->name, '/');
    if (!slash || (size_t)(slash - release->name) >= publisher_size)
        return VCS_PACKAGE_ACCEPT_INVALID; /* codec already forbids this */
    memcpy(publisher, release->name, (size_t)(slash - release->name));
    publisher[slash - release->name] = '\0';
    const struct accept_ns_record *ns = accept_ns_find(accept, publisher);
    if (ns && memcmp(ns->pubkey, release->publisher_pubkey,
                     VCS_PACKAGE_RELEASE_PUBKEY_BYTES) != 0)
        return VCS_PACKAGE_ACCEPT_NAMESPACE;
    *ns_out = ns;
    return VCS_PACKAGE_ACCEPT_OK;
}

static enum vcs_package_accept_result accept_classify_publisher_sequence(
    const struct accept_pub_record *cursor,
    const struct vcs_package_release *release,
    const uint8_t release_id[32])
{
    if (cursor) {
        if (release->publisher_sequence < cursor->sequence)
            return VCS_PACKAGE_ACCEPT_STALE;
        if (release->publisher_sequence == cursor->sequence) {
            if (memcmp(cursor->release_id, release_id, 32) == 0)
                return VCS_PACKAGE_ACCEPT_DUPLICATE;
            return VCS_PACKAGE_ACCEPT_EQUIVOCATION;
        }
    }
    return VCS_PACKAGE_ACCEPT_OK;
}

static enum vcs_package_accept_result accept_commit_release(
    struct vcs_package_accept *accept,
    const struct vcs_package_release *release,
    const uint8_t release_id[32], const char *publisher,
    const struct accept_pub_record *cursor,
    const struct accept_ns_record *ns)
{
    /* Accepted. Bound checks happen BEFORE any mutation so a refusal
     * leaves the state untouched. */
    if (!cursor && accept->pubs_count >= VCS_PACKAGE_ACCEPT_MAX_PUBLISHERS)
        return VCS_PACKAGE_ACCEPT_ERR_LIMIT;
    if (!ns && accept->ns_count >= VCS_PACKAGE_ACCEPT_MAX_NAMESPACES)
        return VCS_PACKAGE_ACCEPT_ERR_LIMIT;
    if (!accept_pub_record(accept, release->publisher_pubkey,
                           release->publisher_sequence, release_id))
        return VCS_PACKAGE_ACCEPT_ERR_ALLOC;
    if (!ns && !accept_ns_bind(accept, publisher,
                               release->publisher_pubkey))
        return VCS_PACKAGE_ACCEPT_ERR_ALLOC;
    return VCS_PACKAGE_ACCEPT_OK;
}

enum vcs_package_accept_result vcs_package_accept(
    struct vcs_package_accept *accept,
    const struct vcs_package_release *release)
{
    if (!accept || !release)
        LOG_RETURN(VCS_PACKAGE_ACCEPT_ERR_NULL, "vcs.accept",
                   "null accept context/release");

    /* 1. The envelope itself must verify. */
    uint8_t release_id[VCS_PACKAGE_RELEASE_ID_BYTES];
    enum vcs_package_accept_result verified =
        accept_verified_release_id(release, release_id);
    if (verified != VCS_PACKAGE_ACCEPT_OK)
        return verified;

    /* 2. The release must name the active chain. */
    char want_chain[VCS_PACKAGE_RELEASE_CHAIN_ID_MAX + 1u];
    if (!vcs_package_accept_chain_id(want_chain, sizeof(want_chain)))
        LOG_RETURN(VCS_PACKAGE_ACCEPT_ERR_NULL, "vcs.accept",
                   "no active chain params");
    if (strcmp(release->chain_id, want_chain) != 0)
        return VCS_PACKAGE_ACCEPT_CHAIN_ID;

    /* 3. The reward address must be a transparent address on this chain. */
    if (!accept_reward_valid(release->reward_address))
        return VCS_PACKAGE_ACCEPT_REWARD;

    /* 4. The publisher namespace is bound first-come to one key. */
    char publisher[VCS_PACKAGE_RELEASE_NAME_HALF_MAX + 1u];
    const struct accept_ns_record *ns = NULL;
    enum vcs_package_accept_result namespace =
        accept_publisher_namespace(accept, release, publisher,
                                   sizeof(publisher), &ns);
    if (namespace != VCS_PACKAGE_ACCEPT_OK)
        return namespace;

    /* 5. Publisher-sequence classification. */
    struct accept_pub_record *cursor =
        accept_pub_find(accept, release->publisher_pubkey);
    enum vcs_package_accept_result sequence =
        accept_classify_publisher_sequence(cursor, release, release_id);
    if (sequence != VCS_PACKAGE_ACCEPT_OK)
        return sequence;

    return accept_commit_release(accept, release, release_id, publisher,
                                 cursor, ns);
}

bool vcs_package_accept_lookup(const struct vcs_package_accept *accept,
                               const uint8_t publisher_pubkey[33],
                               uint64_t *sequence_out,
                               uint8_t release_id_out[32])
{
    if (!accept || !publisher_pubkey)
        return false;
    for (size_t i = 0; i < accept->pubs_count; i++) {
        if (memcmp(accept->pubs[i].pubkey, publisher_pubkey,
                   VCS_PACKAGE_RELEASE_PUBKEY_BYTES) == 0) {
            if (sequence_out)
                *sequence_out = accept->pubs[i].sequence;
            if (release_id_out)
                memcpy(release_id_out, accept->pubs[i].release_id, 32);
            return true;
        }
    }
    return false;
}
