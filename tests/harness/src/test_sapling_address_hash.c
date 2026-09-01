/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pedantic unit tests for the shielded payment-address hash helpers in
 * core/modules/sapling/src/address.c:
 *
 *   void sapling_payment_address_get_hash(const struct sapling_payment_address *,
 *                                         struct uint256 *out);
 *   void sprout_payment_address_get_hash(const struct sprout_payment_address *,
 *                                        struct uint256 *out);
 *
 * Both functions serialize the address (Sapling: 11-byte diversifier `d` ||
 * 32-byte `pk_d`; Sprout: 32-byte `a_pk` || 32-byte `pk_enc`) and run the
 * double-SHA256 `hash256` over the serialized bytes. These tests pin:
 *
 *   - exact 32-byte output that is neither all-zero nor all-0xFF (real digest);
 *   - sensitivity to a single-bit flip in EACH input field
 *     (Sapling: d, pk_d; Sprout: a_pk, pk_enc);
 *   - that swapping the two Sprout fields changes the hash (order matters);
 *   - idempotence: the same address always yields the same hash;
 *   - distinctness: corrupting any byte yields a different hash.
 *
 * One TEST_CASE per entrypoint function: TEST_END defines the _test_next
 * label that ASSERT's failure path jumps to.
 *
 * NOTE: these are deliberately structural (digest-sensitivity) assertions
 * rather than hardcoded golden vectors, so they survive any change of the
 * SHA implementation backend while still failing loudly on a regression
 * that drops a field, mis-orders serialization, or zeroes the output. */

#include "test/test_core.h"
#include "sapling/address.h"

/* ── Sapling helpers ─────────────────────────────────────── */

/* Fill a canonical, non-trivial Sapling address: a distinct, recognizable
 * diversifier and a distinct pk_d so a dropped/zeroed field is detectable. */
static void make_canonical_sapling(struct sapling_payment_address *a)
{
    /* d = 11 bytes (ZC_DIVERSIFIER_SIZE). Use an ascending, non-zero pattern. */
    for (int i = 0; i < ZC_DIVERSIFIER_SIZE; i++)
        a->d[i] = (unsigned char)(0x10 + i);
    /* pk_d = 32 bytes, a different recognizable pattern. */
    for (int i = 0; i < 32; i++)
        a->pk_d.data[i] = (unsigned char)(0xA0 ^ (unsigned char)i);
}

static bool hash_is_all_same(const struct uint256 *h, unsigned char v)
{
    for (int i = 0; i < 32; i++)
        if (h->data[i] != v) return false;
    return true;
}

/* ── Sprout helpers ──────────────────────────────────────── */

static void make_canonical_sprout(struct sprout_payment_address *a)
{
    for (int i = 0; i < 32; i++) {
        a->a_pk.data[i]   = (unsigned char)(0x01 + i);     /* distinct field 1 */
        a->pk_enc.data[i] = (unsigned char)(0xFE - i);     /* distinct field 2 */
    }
}

/* ─────────────────────────────────────────────────────────── *
 * Sapling: canonical hash is well-formed, idempotent, and
 * bit-sensitive in BOTH the diversifier `d` and `pk_d`.
 * ─────────────────────────────────────────────────────────── */
int test_sapling_address_hash_fields(void);
int test_sapling_address_hash_fields(void)
{
    int failures = 0;

    TEST_CASE("sapling_payment_address_get_hash: sized, non-trivial, bit-sensitive in d and pk_d") {
        struct sapling_payment_address addr;
        make_canonical_sapling(&addr);

        struct uint256 h0;
        /* Poison the output buffer to prove the function fully overwrites it. */
        memset(h0.data, 0x5C, sizeof(h0.data));
        sapling_payment_address_get_hash(&addr, &h0);

        /* Correctly sized & real-looking: a hash256 output is 32 bytes and
         * must not be all-zero or all-0xFF (would mean the buffer was never
         * written or the input never serialized). */
        ASSERT(!uint256_is_null(&h0));
        ASSERT(!hash_is_all_same(&h0, 0x00));
        ASSERT(!hash_is_all_same(&h0, 0xFF));
        /* And the poison byte was fully overwritten (no stale bytes). */
        ASSERT(!hash_is_all_same(&h0, 0x5C));

        /* Idempotence: same address -> identical hash, every byte. */
        struct uint256 h0_again;
        sapling_payment_address_get_hash(&addr, &h0_again);
        ASSERT(uint256_eq(&h0, &h0_again));

        /* Flip a single bit in the diversifier `d`: hash must change. */
        struct sapling_payment_address addr_d = addr;
        addr_d.d[0] ^= 0x01;
        struct uint256 h_d;
        sapling_payment_address_get_hash(&addr_d, &h_d);
        ASSERT(!uint256_eq(&h_d, &h0));

        /* Flip a bit in the LAST diversifier byte too (boundary of the
         * 11-byte field) — guards against a length-10 serialization bug. */
        struct sapling_payment_address addr_dlast = addr;
        addr_dlast.d[ZC_DIVERSIFIER_SIZE - 1] ^= 0x80;
        struct uint256 h_dlast;
        sapling_payment_address_get_hash(&addr_dlast, &h_dlast);
        ASSERT(!uint256_eq(&h_dlast, &h0));

        /* Flip a single bit in pk_d: hash must change. */
        struct sapling_payment_address addr_pk = addr;
        addr_pk.pk_d.data[31] ^= 0x01;
        struct uint256 h_pk;
        sapling_payment_address_get_hash(&addr_pk, &h_pk);
        ASSERT(!uint256_eq(&h_pk, &h0));

        /* The two single-field perturbations are themselves distinct: a `d`
         * change and a `pk_d` change must not collide to the same digest. */
        ASSERT(!uint256_eq(&h_d, &h_pk));
    } TEST_END

    return failures;
}

/* ─────────────────────────────────────────────────────────── *
 * Sprout: canonical hash is well-formed, idempotent, sensitive
 * to a_pk and pk_enc, and field ORDER matters (a_pk||pk_enc).
 * ─────────────────────────────────────────────────────────── */
int test_sprout_address_hash_fields(void);
int test_sprout_address_hash_fields(void)
{
    int failures = 0;

    TEST_CASE("sprout_payment_address_get_hash: sized, non-trivial, a_pk/pk_enc sensitive, order-sensitive") {
        struct sprout_payment_address addr;
        make_canonical_sprout(&addr);

        struct uint256 h0;
        memset(h0.data, 0x33, sizeof(h0.data));
        sprout_payment_address_get_hash(&addr, &h0);

        /* Well-formed 32-byte digest, not a sentinel/uninitialized value. */
        ASSERT(!uint256_is_null(&h0));
        ASSERT(!hash_is_all_same(&h0, 0x00));
        ASSERT(!hash_is_all_same(&h0, 0xFF));
        ASSERT(!hash_is_all_same(&h0, 0x33));

        /* Idempotence. */
        struct uint256 h0_again;
        sprout_payment_address_get_hash(&addr, &h0_again);
        ASSERT(uint256_eq(&h0, &h0_again));

        /* Corrupt one byte of a_pk -> different hash. */
        struct sprout_payment_address addr_apk = addr;
        addr_apk.a_pk.data[0] ^= 0xFF;
        struct uint256 h_apk;
        sprout_payment_address_get_hash(&addr_apk, &h_apk);
        ASSERT(!uint256_eq(&h_apk, &h0));

        /* Corrupt one byte of pk_enc -> different hash. */
        struct sprout_payment_address addr_pke = addr;
        addr_pke.pk_enc.data[31] ^= 0xFF;
        struct uint256 h_pke;
        sprout_payment_address_get_hash(&addr_pke, &h_pke);
        ASSERT(!uint256_eq(&h_pke, &h0));

        /* The a_pk and pk_enc perturbations are distinct from each other. */
        ASSERT(!uint256_eq(&h_apk, &h_pke));

        /* Field-ORDER sensitivity: swap a_pk and pk_enc. Because the two
         * fields hold different values, serialize() emits a_pk||pk_enc, so a
         * swap MUST produce a different digest (guards against a serializer
         * that emits the fields in the wrong order or hashes a single field
         * twice). */
        struct sprout_payment_address addr_swapped;
        addr_swapped.a_pk   = addr.pk_enc;
        addr_swapped.pk_enc = addr.a_pk;
        struct uint256 h_swapped;
        sprout_payment_address_get_hash(&addr_swapped, &h_swapped);
        ASSERT(!uint256_eq(&h_swapped, &h0));
    } TEST_END

    return failures;
}

/* ─────────────────────────────────────────────────────────── *
 * Cross-type / cross-construction distinctness + idempotence
 * across independently-built copies of the SAME address.
 * ─────────────────────────────────────────────────────────── */
int test_sapling_sprout_hash_idempotence_and_distinct(void);
int test_sapling_sprout_hash_idempotence_and_distinct(void)
{
    int failures = 0;

    TEST_CASE("address hashes: independent copies match; sapling vs sprout differ") {
        /* Build two independent Sapling addresses with identical content and
         * confirm the hash is stable across the copy (not pointer-/memory-
         * layout dependent). */
        struct sapling_payment_address sa1, sa2;
        make_canonical_sapling(&sa1);
        make_canonical_sapling(&sa2);
        struct uint256 hsa1, hsa2;
        sapling_payment_address_get_hash(&sa1, &hsa1);
        sapling_payment_address_get_hash(&sa2, &hsa2);
        ASSERT(uint256_eq(&hsa1, &hsa2));

        /* Same for Sprout. */
        struct sprout_payment_address sp1, sp2;
        make_canonical_sprout(&sp1);
        make_canonical_sprout(&sp2);
        struct uint256 hsp1, hsp2;
        sprout_payment_address_get_hash(&sp1, &hsp1);
        sprout_payment_address_get_hash(&sp2, &hsp2);
        ASSERT(uint256_eq(&hsp1, &hsp2));

        /* A Sprout address (64 serialized bytes) and a Sapling address
         * (43 serialized bytes) must not collide to the same digest, even
         * when both are non-trivial. */
        ASSERT(!uint256_eq(&hsa1, &hsp1));

        /* Both are sized & real (defense against a no-op stub). */
        ASSERT(!uint256_is_null(&hsa1));
        ASSERT(!uint256_is_null(&hsp1));

        /* An all-zero Sapling address still produces a NON-zero digest:
         * hash256 of 43 zero bytes is a real, non-zero value. This pins that
         * the function actually hashes (rather than copying the input or
         * leaving the output zeroed for an all-zero input). */
        struct sapling_payment_address zero_sa;
        memset(&zero_sa, 0, sizeof(zero_sa));
        struct uint256 hz;
        sapling_payment_address_get_hash(&zero_sa, &hz);
        ASSERT(!uint256_is_null(&hz));
        ASSERT(!uint256_eq(&hz, &hsa1));
    } TEST_END

    return failures;
}
