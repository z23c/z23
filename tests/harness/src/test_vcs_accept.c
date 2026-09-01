/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_vcs_accept — the node-bound acceptance layer gate
 * (contexts/commons/modules/vcs/package_accept.*).
 *
 * Coverage:
 *   1. Canonical chain id helper ("zclassic-" + active strNetworkID).
 *   2. Accept + publisher cursor lookup.
 *   3. Sequence classification: DUPLICATE (idempotent no-op),
 *      EQUIVOCATION (same sequence, different release id), STALE (below
 *      the cursor), and a higher sequence advancing the cursor.
 *   4. Node-bound checks: wrong chain id, non-transparent reward address,
 *      empty reward allowed.
 *   5. Namespace first-come binding: another key cannot claim a bound
 *      publisher namespace; the binding key may publish more under it.
 *   6. Envelope failures map to ACCEPT_INVALID; null arguments map to
 *      ACCEPT_ERR_NULL; every result has a stable string.
 *
 * Node-bound but not node-mutating: the acceptance state is in-memory and
 * per-context; the test pins CHAIN_MAIN so the chain-id and reward rules
 * are deterministic regardless of runner order. */

#include "test/test_core.h"

#include "vcs/package_accept.h"

#include "chain/chainparams.h"
#include "core/uint256.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"

#include <stdio.h>
#include <string.h>

#define VA_CHECK(name, expr) do {                                     \
    if (expr) { printf("  vcs_accept: %s... OK\n", (name)); }         \
    else { printf("  vcs_accept: %s... FAIL\n", (name)); failures++; } \
} while (0)

static bool va_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static bool va_sign(struct vcs_package_release *r, struct privkey *sk)
{
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(r, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(sk, &hash, compact))
        return false;
    memcpy(r->signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    return true;
}

/* A real t1 (P2PKH) address of the active chain from a fixed 20-byte
 * payload — the acceptance reward rule needs a genuinely decodable
 * transparent address, not a charset-plausible string. */
static bool va_t1_reward(char *out, size_t out_size)
{
    const struct chain_params *params = chain_params_get();
    if (!params)
        return false;
    size_t pubkey_len = 0;
    size_t script_len = 0;
    const unsigned char *pubkey_prefix =
        chain_params_base58_prefix(params, B58_PUBKEY_ADDRESS, &pubkey_len);
    const unsigned char *script_prefix =
        chain_params_base58_prefix(params, B58_SCRIPT_ADDRESS, &script_len);
    if (!pubkey_prefix || !script_prefix)
        return false;
    struct tx_destination dest;
    dest.type = DEST_KEY_ID;
    memset(dest.id.key.id.data, 0x33, 20);
    return encode_destination(&dest, pubkey_prefix, pubkey_len,
                              script_prefix, script_len, out, out_size);
}

/* A valid, signed release under the seed'd key: active chain id, real t1
 * reward, no parent, no znam. */
static bool va_fixture(struct vcs_package_release *r, uint8_t key_seed,
                       uint64_t sequence, const char *name)
{
    memset(r, 0, sizeof(*r));
    struct privkey sk;
    struct pubkey pk;
    if (!va_keypair(key_seed, &sk, &pk))
        return false;

    r->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(r->name, sizeof(r->name), "%s", name);
    snprintf(r->semver, sizeof(r->semver), "1.4.2");
    for (int i = 0; i < 32; i++) {
        r->package_root[i] = (uint8_t)i;
        r->recipe_root[i]  = (uint8_t)(0x40 + i);
    }
    r->has_parent = false;
    memcpy(r->publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    r->publisher_sequence = sequence;
    if (!va_t1_reward(r->reward_address, sizeof(r->reward_address)))
        return false;
    snprintf(r->license, sizeof(r->license), "Apache-2.0");
    r->has_znam = false;
    if (!vcs_package_accept_chain_id(r->chain_id, sizeof(r->chain_id)))
        return false;
    return va_sign(r, &sk);
}

/* ── 1/2: chain id helper, accept, cursor lookup ──────────────────── */
static int t_accept_happy_path(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);

    char chain_id[VCS_PACKAGE_RELEASE_CHAIN_ID_MAX + 1u];
    VA_CHECK("chain: canonical id computes",
             vcs_package_accept_chain_id(chain_id, sizeof(chain_id)));
    VA_CHECK("chain: main id is zclassic-main",
             strcmp(chain_id, "zclassic-main") == 0);
    VA_CHECK("chain: tiny buffer refused",
             !vcs_package_accept_chain_id(chain_id, 4u));
    VA_CHECK("chain: null out refused",
             !vcs_package_accept_chain_id(NULL, sizeof(chain_id)));

    struct vcs_package_accept *accept = vcs_package_accept_new();
    VA_CHECK("accept: context allocates", accept != NULL);
    if (!accept)
        return failures;

    struct vcs_package_release r;
    VA_CHECK("accept: fixture builds + signs", va_fixture(&r, 0x11, 7u,
                                                          "rhett/ring-buffer"));
    VA_CHECK("accept: valid release accepted",
             vcs_package_accept(accept, &r) == VCS_PACKAGE_ACCEPT_OK);

    uint8_t want_id[VCS_PACKAGE_RELEASE_ID_BYTES];
    VA_CHECK("accept: release id computes",
             vcs_package_release_id(&r, want_id) == VCS_PACKAGE_RELEASE_OK);
    uint64_t seq = 0;
    uint8_t got_id[VCS_PACKAGE_RELEASE_ID_BYTES];
    VA_CHECK("accept: cursor recorded",
             vcs_package_accept_lookup(accept, r.publisher_pubkey, &seq,
                                       got_id));
    VA_CHECK("accept: cursor matches the accepted release",
             seq == 7u && memcmp(got_id, want_id, 32) == 0);

    struct privkey sk2;
    struct pubkey pk2;
    VA_CHECK("accept: second key", va_keypair(0x22, &sk2, &pk2));
    VA_CHECK("accept: unknown publisher has no cursor",
             !vcs_package_accept_lookup(accept, pk2.vch, &seq, got_id));
    VA_CHECK("accept: lookup tolerates null outs",
             vcs_package_accept_lookup(accept, r.publisher_pubkey, NULL,
                                       NULL));
    VA_CHECK("accept: lookup rejects null args",
             !vcs_package_accept_lookup(NULL, r.publisher_pubkey, &seq,
                                        got_id) &&
             !vcs_package_accept_lookup(accept, NULL, &seq, got_id));

    vcs_package_accept_free(accept);
    vcs_package_accept_free(NULL); /* free(NULL) is a no-op */
    return failures;
}

/* ── 3: sequence classification ───────────────────────────────────── */
static int t_accept_sequence_rules(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    struct vcs_package_accept *accept = vcs_package_accept_new();
    VA_CHECK("seq: context allocates", accept != NULL);
    if (!accept)
        return failures;

    struct vcs_package_release r;
    VA_CHECK("seq: fixture", va_fixture(&r, 0x11, 7u, "rhett/ring-buffer"));
    uint8_t first_id[VCS_PACKAGE_RELEASE_ID_BYTES];
    VA_CHECK("seq: first id computes",
             vcs_package_release_id(&r, first_id) == VCS_PACKAGE_RELEASE_OK);
    VA_CHECK("seq: first release accepted",
             vcs_package_accept(accept, &r) == VCS_PACKAGE_ACCEPT_OK);

    /* Redelivery of the exact same release is an idempotent no-op. */
    VA_CHECK("seq: redelivery is DUPLICATE",
             vcs_package_accept(accept, &r) == VCS_PACKAGE_ACCEPT_DUPLICATE);
    uint64_t seq = 0;
    uint8_t got_id[VCS_PACKAGE_RELEASE_ID_BYTES];
    VA_CHECK("seq: duplicate left the cursor untouched",
             vcs_package_accept_lookup(accept, r.publisher_pubkey, &seq,
                                       got_id) &&
             seq == 7u && memcmp(got_id, first_id, 32) == 0);

    /* Same sequence, different content: the publisher signed two different
     * releases with one sequence number. Rejected, never recorded. */
    struct vcs_package_release forked;
    VA_CHECK("seq: equivocation fixture",
             va_fixture(&forked, 0x11, 7u, "rhett/ring-buffer-fork"));
    uint8_t forked_id[VCS_PACKAGE_RELEASE_ID_BYTES];
    VA_CHECK("seq: equivocation id computes",
             vcs_package_release_id(&forked, forked_id) ==
                 VCS_PACKAGE_RELEASE_OK);
    VA_CHECK("seq: equivocation differs from the accepted release",
             memcmp(forked_id, first_id, 32) != 0);
    VA_CHECK("seq: equivocation rejected",
             vcs_package_accept(accept, &forked) ==
                 VCS_PACKAGE_ACCEPT_EQUIVOCATION);
    VA_CHECK("seq: equivocation left the cursor untouched",
             vcs_package_accept_lookup(accept, r.publisher_pubkey, &seq,
                                       got_id) &&
             seq == 7u && memcmp(got_id, first_id, 32) == 0);

    /* A higher sequence advances the cursor. */
    struct vcs_package_release newer;
    VA_CHECK("seq: newer fixture",
             va_fixture(&newer, 0x11, 8u, "rhett/ring-buffer"));
    uint8_t newer_id[VCS_PACKAGE_RELEASE_ID_BYTES];
    VA_CHECK("seq: newer id computes",
             vcs_package_release_id(&newer, newer_id) ==
                 VCS_PACKAGE_RELEASE_OK);
    VA_CHECK("seq: higher sequence accepted",
             vcs_package_accept(accept, &newer) == VCS_PACKAGE_ACCEPT_OK);
    VA_CHECK("seq: cursor advanced",
             vcs_package_accept_lookup(accept, r.publisher_pubkey, &seq,
                                       got_id) &&
             seq == 8u && memcmp(got_id, newer_id, 32) == 0);

    /* Anything below the cursor is stale — even a well-formed, correctly
     * signed release. */
    struct vcs_package_release stale;
    VA_CHECK("seq: stale fixture",
             va_fixture(&stale, 0x11, 6u, "rhett/ring-buffer"));
    VA_CHECK("seq: lower sequence is STALE",
             vcs_package_accept(accept, &stale) == VCS_PACKAGE_ACCEPT_STALE);
    /* ... including redelivery of the now-superseded sequence 7. */
    VA_CHECK("seq: superseded sequence is STALE, not DUPLICATE",
             vcs_package_accept(accept, &r) == VCS_PACKAGE_ACCEPT_STALE);
    VA_CHECK("seq: stale left the cursor untouched",
             vcs_package_accept_lookup(accept, r.publisher_pubkey, &seq,
                                       got_id) &&
             seq == 8u && memcmp(got_id, newer_id, 32) == 0);

    vcs_package_accept_free(accept);
    return failures;
}

/* ── 4: node-bound checks (chain id, reward) ──────────────────────── */
static int t_accept_node_bound_rules(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    struct vcs_package_accept *accept = vcs_package_accept_new();
    VA_CHECK("node: context allocates", accept != NULL);
    if (!accept)
        return failures;

    struct privkey sk;
    struct pubkey pk;
    VA_CHECK("node: key", va_keypair(0x11, &sk, &pk));

    /* Wrong chain id: a correctly signed release naming another chain. */
    struct vcs_package_release r;
    VA_CHECK("node: fixture", va_fixture(&r, 0x11, 1u, "rhett/ring-buffer"));
    snprintf(r.chain_id, sizeof(r.chain_id), "zclassic-test");
    VA_CHECK("node: wrong-chain release re-signs", va_sign(&r, &sk));
    VA_CHECK("node: wrong chain id rejected",
             vcs_package_accept(accept, &r) == VCS_PACKAGE_ACCEPT_CHAIN_ID);
    VA_CHECK("node: wrong-chain rejection recorded nothing",
             !vcs_package_accept_lookup(accept, r.publisher_pubkey, NULL,
                                        NULL));

    /* Reward must be a transparent address: a charset-valid but
     * undecodable string is rejected, and so is a valid address of
     * another chain (a t1 minted under the testnet version bytes). */
    VA_CHECK("node: fixture 2", va_fixture(&r, 0x11, 1u,
                                           "rhett/ring-buffer"));
    snprintf(r.reward_address, sizeof(r.reward_address), "%s",
             "t1ThisIsNotDecodable");
    VA_CHECK("node: bad-reward release re-signs", va_sign(&r, &sk));
    VA_CHECK("node: undecodable reward rejected",
             vcs_package_accept(accept, &r) == VCS_PACKAGE_ACCEPT_REWARD);

    chain_params_select(CHAIN_TESTNET);
    char foreign_t1[64];
    VA_CHECK("node: foreign-chain t1 mints",
             va_t1_reward(foreign_t1, sizeof(foreign_t1)));
    chain_params_select(CHAIN_MAIN);
    VA_CHECK("node: fixture 3", va_fixture(&r, 0x11, 1u,
                                           "rhett/ring-buffer"));
    snprintf(r.reward_address, sizeof(r.reward_address), "%s", foreign_t1);
    VA_CHECK("node: foreign-reward release re-signs", va_sign(&r, &sk));
    VA_CHECK("node: other-chain reward rejected",
             vcs_package_accept(accept, &r) == VCS_PACKAGE_ACCEPT_REWARD);
    VA_CHECK("node: reward rejection recorded nothing",
             !vcs_package_accept_lookup(accept, r.publisher_pubkey, NULL,
                                        NULL));

    /* Empty reward ("no reward address") is allowed. */
    VA_CHECK("node: fixture 4", va_fixture(&r, 0x11, 1u,
                                           "rhett/ring-buffer"));
    r.reward_address[0] = '\0';
    VA_CHECK("node: empty-reward release re-signs", va_sign(&r, &sk));
    VA_CHECK("node: empty reward accepted",
             vcs_package_accept(accept, &r) == VCS_PACKAGE_ACCEPT_OK);

    vcs_package_accept_free(accept);
    return failures;
}

/* ── 5: namespace first-come binding ──────────────────────────────── */
static int t_accept_namespace_binding(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    struct vcs_package_accept *accept = vcs_package_accept_new();
    VA_CHECK("ns: context allocates", accept != NULL);
    if (!accept)
        return failures;

    /* Key A binds "rhett" with its first accepted release. */
    struct vcs_package_release a1;
    VA_CHECK("ns: key A fixture", va_fixture(&a1, 0x11, 1u,
                                             "rhett/ring-buffer"));
    VA_CHECK("ns: first release binds the namespace",
             vcs_package_accept(accept, &a1) == VCS_PACKAGE_ACCEPT_OK);

    /* A different key cannot publish into "rhett", even with a fresh
     * sequence cursor and a valid signature. */
    struct vcs_package_release b1;
    VA_CHECK("ns: key B fixture", va_fixture(&b1, 0x22, 1u,
                                             "rhett/ring-buffer"));
    VA_CHECK("ns: foreign key in a bound namespace rejected",
             vcs_package_accept(accept, &b1) == VCS_PACKAGE_ACCEPT_NAMESPACE);
    VA_CHECK("ns: namespace rejection recorded no cursor",
             !vcs_package_accept_lookup(accept, b1.publisher_pubkey, NULL,
                                        NULL));

    /* The binding key may publish more packages under its namespace. */
    struct vcs_package_release a2;
    VA_CHECK("ns: key A second package fixture",
             va_fixture(&a2, 0x11, 2u, "rhett/other-tool"));
    VA_CHECK("ns: bound key reuses its namespace",
             vcs_package_accept(accept, &a2) == VCS_PACKAGE_ACCEPT_OK);

    /* And the other key is fine in its own namespace. */
    struct vcs_package_release b2;
    VA_CHECK("ns: key B own-namespace fixture",
             va_fixture(&b2, 0x22, 1u, "bob/ring-buffer"));
    VA_CHECK("ns: other key in a free namespace accepted",
             vcs_package_accept(accept, &b2) == VCS_PACKAGE_ACCEPT_OK);

    vcs_package_accept_free(accept);
    return failures;
}

/* ── 6: envelope failures, nulls, result strings ──────────────────── */
static int t_accept_invalid_and_strings(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    struct vcs_package_accept *accept = vcs_package_accept_new();
    VA_CHECK("misc: context allocates", accept != NULL);
    if (!accept)
        return failures;

    struct vcs_package_release r;
    VA_CHECK("misc: fixture", va_fixture(&r, 0x11, 1u, "rhett/ring-buffer"));

    VA_CHECK("misc: null context rejected",
             vcs_package_accept(NULL, &r) == VCS_PACKAGE_ACCEPT_ERR_NULL);
    VA_CHECK("misc: null release rejected",
             vcs_package_accept(accept, NULL) == VCS_PACKAGE_ACCEPT_ERR_NULL);

    /* A corrupted signature fails the envelope check before any
     * node-bound or state rule runs. */
    struct vcs_package_release bad = r;
    bad.signature[0] ^= 0x01u;
    VA_CHECK("misc: bad signature maps to INVALID",
             vcs_package_accept(accept, &bad) == VCS_PACKAGE_ACCEPT_INVALID);

    /* A codec-level grammar failure (zero sequence) is INVALID too. */
    bad = r;
    bad.publisher_sequence = 0;
    VA_CHECK("misc: codec-invalid release maps to INVALID",
             vcs_package_accept(accept, &bad) == VCS_PACKAGE_ACCEPT_INVALID);
    VA_CHECK("misc: INVALID recorded nothing",
             !vcs_package_accept_lookup(accept, r.publisher_pubkey, NULL,
                                        NULL));

    for (int e = 0; e <= VCS_PACKAGE_ACCEPT_ERR_LIMIT; e++)
        VA_CHECK("misc: result string defined",
                 vcs_package_accept_result_string(
                     (enum vcs_package_accept_result)e) != NULL);

    vcs_package_accept_free(accept);
    return failures;
}

int test_vcs_accept(void)
{
    printf("\n=== vcs_accept: node-bound release acceptance ===\n");
    int failures = 0;
    failures += t_accept_happy_path();
    failures += t_accept_sequence_rules();
    failures += t_accept_node_bound_rules();
    failures += t_accept_namespace_binding();
    failures += t_accept_invalid_and_strings();
    printf("=== vcs_accept complete: %d failure(s) ===\n", failures);
    return failures;
}
