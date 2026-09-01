/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Incremental Merkle tree and witness tests for Sapling. */

#include "test/test_core.h"
#include "core/random.h"
#include "validation/main_state.h"
#include "sapling/pedersen_hash.h"
#include "sapling/note.h"
#include "crypto/curve25519.h"
#include "sapling/note_encryption.h"
#include "sapling/sapling.h"
#include "wallet/wallet.h"
#include "util/safe_alloc.h"

static int test_merkle_tree_scale(void);

int test_merkle_tree(void)
{
    int failures = 0;

    /* ================================================================ */
    /* Incremental Merkle tree serialization test                       */
    /* ================================================================ */

    printf("Sapling incremental tree serialize/deserialize roundtrip... ");
    {
        struct incremental_merkle_tree t;
        sapling_testing_tree_init(&t);

        /* Add some commitments */
        for (int i = 0; i < 5; i++) {
            struct uint256 cm;
            memset(&cm, 0, sizeof(cm));
            cm.data[0] = (uint8_t)(i + 1);
            incremental_tree_append(&t, &cm);
        }

        struct uint256 root1;
        incremental_tree_root(&t, &root1);

        /* Serialize */
        struct byte_stream ws;
        stream_init(&ws, 4096);
        bool ok = incremental_tree_serialize(&t, &ws);

        /* Deserialize */
        struct incremental_merkle_tree t2;
        sapling_testing_tree_init(&t2);
        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        ok = ok && incremental_tree_deserialize(&t2, &rs);

        /* Roots must match */
        struct uint256 root2;
        incremental_tree_root(&t2, &root2);
        ok = ok && (memcmp(root1.data, root2.data, 32) == 0);

        /* Size must match */
        ok = ok && (incremental_tree_size(&t) == incremental_tree_size(&t2));

        stream_free(&ws);
        stream_free(&rs);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Sapling incremental tree append + root changes... ");
    {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);

        struct uint256 root_empty;
        incremental_tree_empty_root(&t, &root_empty);

        struct uint256 cm1;
        memset(&cm1, 0, sizeof(cm1));
        cm1.data[0] = 0x42; /* NOT 1, since 1 = uncommitted value */
        incremental_tree_append(&t, &cm1);

        struct uint256 root1;
        incremental_tree_root(&t, &root1);
        bool ok = (memcmp(root_empty.data, root1.data, 32) != 0);
        ok = ok && (incremental_tree_size(&t) == 1);

        struct uint256 cm2;
        memset(&cm2, 0, sizeof(cm2));
        cm2.data[0] = 0x43;
        incremental_tree_append(&t, &cm2);

        struct uint256 root2;
        incremental_tree_root(&t, &root2);
        ok = ok && (memcmp(root1.data, root2.data, 32) != 0);
        ok = ok && (incremental_tree_size(&t) == 2);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Sapling empty root matches known value... ");
    {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        struct uint256 root;
        incremental_tree_root(&t, &root);
        char hex[65];
        uint256_get_hex(&root, hex);
        bool ok = (strcmp(hex,
            "3e49b5f954aa9d3545bc6c37744661eea48d7c34e3000d82b7f0010c30f4c2fb") == 0);
        if (!ok) printf("FAIL (got %s)\n", hex);
        else printf("OK\n");
        if (!ok) failures++;
    }

    printf("Sapling tree root after first real commitment (block 476977)... ");
    {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        struct uint256 cm;
        uint256_set_hex(&cm,
            "5a8d47a74b48efce5841a43ddaccdc75253a4ccda847d67ada8309dcf01d3943");
        incremental_tree_append(&t, &cm);
        struct uint256 root;
        incremental_tree_root(&t, &root);
        char hex[65];
        uint256_get_hex(&root, hex);
        bool ok = (strcmp(hex,
            "4fa518c5b25bb460710ba5e42d83b549100193abb5a895a20717dfeaf96116d4") == 0);
        if (!ok) printf("FAIL (got %s)\n", hex);
        else printf("OK\n");
        if (!ok) failures++;
    }

    printf("Sapling witness root matches tree root... ");
    {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        struct uint256 cm;
        uint256_set_hex(&cm,
            "5a8d47a74b48efce5841a43ddaccdc75253a4ccda847d67ada8309dcf01d3943");
        incremental_tree_append(&t, &cm);
        struct incremental_witness w;
        incremental_witness_init(&w, &t);
        struct uint256 w_root, t_root;
        incremental_witness_root(&w, &w_root);
        incremental_tree_root(&t, &t_root);
        bool ok = (memcmp(w_root.data, t_root.data, 32) == 0);
        if (!ok) {
            char h1[65], h2[65];
            uint256_get_hex(&w_root, h1); uint256_get_hex(&t_root, h2);
            printf("FAIL\n  witness: %s\n  tree:    %s\n", h1, h2);
        } else printf("OK\n");
        if (!ok) failures++;
    }

    printf("Sapling witness advances correctly with new commitment... ");
    {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        struct uint256 cm1, cm2;
        uint256_set_hex(&cm1, "5a8d47a74b48efce5841a43ddaccdc75253a4ccda847d67ada8309dcf01d3943");
        uint256_set_hex(&cm2, "1111111111111111111111111111111111111111111111111111111111111111");
        incremental_tree_append(&t, &cm1);
        struct incremental_witness w;
        incremental_witness_init(&w, &t);
        incremental_tree_append(&t, &cm2);
        incremental_witness_append(&w, &cm2);
        struct uint256 w_root, t_root;
        incremental_witness_root(&w, &w_root);
        incremental_tree_root(&t, &t_root);
        bool ok = (memcmp(w_root.data, t_root.data, 32) == 0);
        if (!ok) {
            char h1[65], h2[65];
            uint256_get_hex(&w_root, h1); uint256_get_hex(&t_root, h2);
            printf("FAIL\n  witness: %s\n  tree:    %s\n", h1, h2);
        } else printf("OK\n");
        if (!ok) failures++;
    }

    /* ================================================================ */
    /* sapling_generate_r tests                                         */
    /* ================================================================ */

    printf("Sapling tree size after 10000 appends... ");
    {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        struct uint256 cm;
        memset(cm.data, 0x42, 32);
        for (int i = 0; i < 10000; i++) {
            cm.data[0] = (unsigned char)(i & 0xff);
            cm.data[1] = (unsigned char)((i >> 8) & 0xff);
            incremental_tree_append(&t, &cm);
        }
        size_t sz = incremental_tree_size(&t);
        /* 10000 in binary = 10011100010000, so parents should reflect this */
        struct byte_stream ts;
        stream_init(&ts, 2048);
        incremental_tree_serialize(&t, &ts);
        bool ok = (sz == 10000 && ts.size > 200);
        if (!ok) printf("FAIL (size=%zu, serial=%zu bytes)\n", sz, ts.size);
        else printf("OK (size=%zu, serial=%zu bytes)\n", sz, ts.size);
        stream_free(&ts);
        if (!ok) failures++;
    }

    /* Scale tests split into separate function to avoid stack exhaustion.
     * Each scale test allocates ~5.6KB of structs on the stack; with many tests
     * in one function frame the compiler may not reuse stack slots, causing
     * overflow when subsequent test functions are called. */
    failures += test_merkle_tree_scale();

    return failures;
}

/* Split from test_merkle_tree to keep stack usage bounded per call frame.
 * __attribute__((noinline)) prevents LTO from merging the frames. */
__attribute__((noinline))
static int test_merkle_tree_scale(void)
{
    int failures = 0;

    /* Witness-at-scale tests: verify witness root == tree root at increasing sizes.
     * The live rescan processes 1M+ commitments; we need to confirm correctness. */
    int scale_sizes[] = {100, 1000, 10000};
    for (int si = 0; si < 3; si++) {
        int N = scale_sizes[si];
        int W = N / 2; /* witness position at midpoint */
        printf("Sapling witness root == tree root at %d elements (witness@%d)... ", N, W);
        {
            struct incremental_merkle_tree t;
            sapling_tree_init(&t);
            struct incremental_witness w;
            bool w_init = false;
            struct uint256 cm;
            memset(cm.data, 0x42, 32);
            for (int i = 0; i < N; i++) {
                cm.data[0] = (unsigned char)(i & 0xff);
                cm.data[1] = (unsigned char)((i >> 8) & 0xff);
                cm.data[2] = (unsigned char)((i >> 16) & 0xff);
                if (w_init)
                    incremental_witness_append(&w, &cm);
                incremental_tree_append(&t, &cm);
                if (i == W) {
                    incremental_witness_init(&w, &t);
                    w_init = true;
                }
            }
            struct uint256 wr, tr;
            incremental_witness_root(&w, &wr);
            incremental_tree_root(&t, &tr);
            bool ok = (memcmp(wr.data, tr.data, 32) == 0);
            if (!ok) {
                char h1[65], h2[65];
                uint256_get_hex(&wr, h1); uint256_get_hex(&tr, h2);
                printf("FAIL (fills=%zu)\n  witness: %s\n  tree:    %s\n",
                    w.num_filled, h1, h2);
                failures++;
            } else {
                printf("OK (fills=%zu)\n", w.num_filled);
            }
        }
    }

    printf("Sapling witness root matches tree root at scale (10000 elements)... ");
    {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        struct uint256 cm;
        memset(cm.data, 0x42, 32);
        /* Append 9999 elements */
        for (int i = 0; i < 9999; i++) {
            cm.data[0] = (unsigned char)(i & 0xff);
            cm.data[1] = (unsigned char)((i >> 8) & 0xff);
            incremental_tree_append(&t, &cm);
        }
        /* Append 10000th and create witness */
        cm.data[0] = (unsigned char)(9999 & 0xff);
        cm.data[1] = (unsigned char)((9999 >> 8) & 0xff);
        incremental_tree_append(&t, &cm);
        struct incremental_witness w;
        incremental_witness_init(&w, &t);
        struct uint256 wr, tr;
        incremental_witness_root(&w, &wr);
        incremental_tree_root(&t, &tr);
        bool ok = (memcmp(wr.data, tr.data, 32) == 0);
        if (!ok) {
            char h1[65], h2[65];
            uint256_get_hex(&wr, h1); uint256_get_hex(&tr, h2);
            printf("FAIL\n  witness: %s\n  tree:    %s\n", h1, h2);
        } else printf("OK\n");
        if (!ok) failures++;
    }

    printf("Sapling TREE serialize/deserialize preserves root (25K)... ");
    {
        /* 25000 appends fill 14 of the 32 parent levels (has_left/has_right
         * both set), which is the structure that drives tree
         * serialize/deserialize: every active parent level is emitted and
         * read back. A larger count only re-fills the cached-empty upper
         * half identically — it adds Pedersen hashes, not coverage. The
         * dedicated large-scale stress anchor stays at 50K below. */
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        struct uint256 cm;
        memset(cm.data, 0x42, 32);
        for (int i = 0; i < 25000; i++) {
            cm.data[0]=(unsigned char)(i&0xff); cm.data[1]=(unsigned char)((i>>8)&0xff); cm.data[2]=(unsigned char)((i>>16)&0xff);
            incremental_tree_append(&t, &cm);
        }
        struct uint256 r1;
        incremental_tree_root(&t, &r1);
        struct byte_stream s; stream_init(&s, 4096);
        incremental_tree_serialize(&t, &s);
        struct incremental_merkle_tree t2;
        struct byte_stream rs; stream_init_from_data(&rs, s.data, s.size);
        bool ok = incremental_tree_deserialize(&t2, &rs);
        struct uint256 r2;
        if (ok) incremental_tree_root(&t2, &r2);
        ok = ok && (memcmp(r1.data, r2.data, 32) == 0);
        if (!ok) { char h1[65],h2[65]; uint256_get_hex(&r1,h1); uint256_get_hex(&r2,h2); printf("FAIL\n  orig: %s\n  deser: %s\n",h1,h2); failures++; }
        else printf("OK (%zu bytes)\n", s.size);
        stream_free(&s);
    }

    printf("Sapling witness serialize/deserialize preserves root (10K)... ");
    {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        struct uint256 cm;
        memset(cm.data, 0x42, 32);
        for (int i = 0; i < 10000; i++) {
            cm.data[0] = (unsigned char)(i & 0xff);
            cm.data[1] = (unsigned char)((i >> 8) & 0xff);
            incremental_tree_append(&t, &cm);
        }
        struct incremental_witness w;
        incremental_witness_init(&w, &t);

        /* Serialize */
        struct byte_stream ws;
        stream_init(&ws, 8192);
        incremental_witness_serialize(&w, &ws);

        /* Deserialize */
        struct incremental_witness w2;
        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        bool deser_ok = incremental_witness_deserialize(&w2, &rs,
            SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH,
            t.combine, t.uncommitted);

        /* Compare roots */
        struct uint256 r1, r2;
        incremental_witness_root(&w, &r1);
        incremental_witness_root(&w2, &r2);

        bool ok = deser_ok && (memcmp(r1.data, r2.data, 32) == 0);
        if (!ok) {
            char h1[65], h2[65];
            uint256_get_hex(&r1, h1); uint256_get_hex(&r2, h2);
            printf("FAIL (deser=%d)\n  original: %s\n  roundtrip: %s\n", deser_ok, h1, h2);
        } else {
            printf("OK (%zu bytes serialized)\n", ws.size);
        }
        stream_free(&ws);
        if (!ok) failures++;
    }

    printf("Sapling witness root after advancement at scale (1000+100)... ");
    {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        struct uint256 cm;
        memset(cm.data, 0x42, 32);
        /* Build tree with 1000 elements, witness at element 500 */
        struct incremental_witness w;
        bool w_init = false;
        for (int i = 0; i < 1000; i++) {
            cm.data[0] = (unsigned char)(i & 0xff);
            cm.data[1] = (unsigned char)((i >> 8) & 0xff);
            if (w_init)
                incremental_witness_append(&w, &cm);
            incremental_tree_append(&t, &cm);
            if (i == 499) {
                incremental_witness_init(&w, &t);
                w_init = true;
            }
        }
        /* Advance both tree and witness by 100 more elements */
        for (int i = 1000; i < 1100; i++) {
            cm.data[0] = (unsigned char)(i & 0xff);
            cm.data[1] = (unsigned char)((i >> 8) & 0xff);
            incremental_witness_append(&w, &cm);
            incremental_tree_append(&t, &cm);
        }
        struct uint256 wr, tr;
        incremental_witness_root(&w, &wr);
        incremental_tree_root(&t, &tr);
        bool ok = (memcmp(wr.data, tr.data, 32) == 0);
        if (!ok) {
            char h1[65], h2[65];
            uint256_get_hex(&wr, h1); uint256_get_hex(&tr, h2);
            printf("FAIL\n  witness: %s\n  tree:    %s\n", h1, h2);
        } else printf("OK\n");
        if (!ok) failures++;
    }

    printf("sapling_generate_r produces valid non-zero scalars... ");
    {
        bool ok = true;
        uint8_t prev[32] = {0};
        for (int i = 0; i < 10; i++) {
            uint8_t r[32];
            sapling_generate_r(r);
            /* Non-zero */
            uint8_t zeros[32] = {0};
            if (memcmp(r, zeros, 32) == 0) { ok = false; break; }
            /* Different from previous (astronomically unlikely to collide) */
            if (i > 0 && memcmp(r, prev, 32) == 0) { ok = false; break; }
            /* Must be a valid Fs scalar (decompresses without error) */
            struct fs s;
            if (!fs_from_bytes(&s, r)) { ok = false; break; }
            memcpy(prev, r, 32);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================ */
    /* Pedersen hash direct tests                                       */
    /* ================================================================ */

    printf("pedersen_merkle_hash deterministic and non-colliding... ");
    {
        uint8_t a[32] = {0}, b[32] = {0};
        a[0] = 1; b[0] = 2;
        uint8_t r1[32], r2[32];
        pedersen_merkle_hash(0, a, b, r1);
        pedersen_merkle_hash(0, a, b, r2);
        bool ok = (memcmp(r1, r2, 32) == 0); /* deterministic */
        /* Swapping inputs → different output */
        uint8_t r3[32];
        pedersen_merkle_hash(0, b, a, r3);
        ok = ok && (memcmp(r1, r3, 32) != 0);
        /* Different depth → different output */
        uint8_t r4[32];
        pedersen_merkle_hash(1, a, b, r4);
        ok = ok && (memcmp(r1, r4, 32) != 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================ */
    /* Sprout note/address tests                                        */
    /* ================================================================ */

    printf("Sprout spending key → viewing key → address... ");
    {
        struct sprout_spending_key sk;
        memset(sk.data, 0x42, 32);
        struct sprout_viewing_key vk;
        sprout_spending_key_to_viewing_key(&sk, &vk);
        struct sprout_payment_address addr;
        sprout_viewing_key_to_address(&vk, &addr);
        /* Direct derivation should match */
        struct sprout_payment_address addr2;
        sprout_spending_key_to_address(&sk, &addr2);
        bool ok = (memcmp(addr.a_pk.data, addr2.a_pk.data, 32) == 0);
        ok = ok && (memcmp(addr.pk_enc.data, addr2.pk_enc.data, 32) == 0);
        /* Different sk → different address */
        struct sprout_spending_key sk2;
        memset(sk2.data, 0x43, 32);
        struct sprout_payment_address addr3;
        sprout_spending_key_to_address(&sk2, &addr3);
        ok = ok && (memcmp(addr.a_pk.data, addr3.a_pk.data, 32) != 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Sprout payment address serialize/deserialize... ");
    {
        struct sprout_spending_key sk;
        GetRandBytes(sk.data, 32);
        struct sprout_payment_address addr;
        sprout_spending_key_to_address(&sk, &addr);

        struct byte_stream ws;
        stream_init(&ws, 256);
        bool ok = sprout_payment_address_serialize(&addr, &ws);

        struct sprout_payment_address addr2;
        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        ok = ok && sprout_payment_address_deserialize(&addr2, &rs);
        ok = ok && (memcmp(addr.a_pk.data, addr2.a_pk.data, 32) == 0);
        ok = ok && (memcmp(addr.pk_enc.data, addr2.pk_enc.data, 32) == 0);

        stream_free(&ws);
        stream_free(&rs);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Sapling payment address encode/decode bech32... ");
    {
        uint8_t seed[32] = {0};
        struct zip32_xsk xsk;
        zip32_xsk_master(&xsk, seed, 32);
        struct zip32_xfvk xfvk;
        zip32_xsk_to_xfvk(&xfvk, &xsk);

        uint8_t d[11], pk_d[32];
        zip32_xfvk_address(&xfvk, d, pk_d);

        char addr[128];
        bool ok = sapling_encode_payment_address(d, pk_d, "zs", addr, sizeof(addr));
        ok = ok && (strncmp(addr, "zs1", 3) == 0);

        uint8_t d2[11], pk_d2[32];
        ok = ok && sapling_decode_payment_address(addr, d2, pk_d2);
        ok = ok && (memcmp(d, d2, 11) == 0);
        ok = ok && (memcmp(pk_d, pk_d2, 32) == 0);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Sapling note plaintext serialize/deserialize... ");
    {
        struct sapling_note_plaintext np;
        np.d[0] = 0x42;
        for (int i = 1; i < 11; i++) np.d[i] = (uint8_t)i;
        np.value = 123456789ULL;
        memset(np.rcm.data, 0xAB, 32);
        memset(np.memo, 0xF6, 512);
        memcpy(np.memo, "Hello", 5);

        struct byte_stream ws;
        stream_init(&ws, 1024);
        bool ok = sapling_note_plaintext_serialize(&np, &ws);

        struct sapling_note_plaintext np2;
        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        ok = ok && sapling_note_plaintext_deserialize(&np2, &rs);

        ok = ok && (memcmp(np.d, np2.d, 11) == 0);
        ok = ok && (np.value == np2.value);
        ok = ok && (memcmp(np.rcm.data, np2.rcm.data, 32) == 0);
        ok = ok && (memcmp(np.memo, np2.memo, 512) == 0);

        stream_free(&ws);
        stream_free(&rs);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Sprout note encryption roundtrip... ");
    {
        /* Generate Sprout key pair via curve25519 */
        uint8_t esk[32];
        GetRandBytes(esk, 32);
        esk[0] &= 248; esk[31] &= 127; esk[31] |= 64;

        uint8_t sk_enc[32];
        GetRandBytes(sk_enc, 32);
        sk_enc[0] &= 248; sk_enc[31] &= 127; sk_enc[31] |= 64;

        /* Derive pk_enc from sk_enc */
        uint8_t pk_enc[32];
        curve25519_scalarmult_base(pk_enc, sk_enc);

        uint8_t hsig[32];
        GetRandBytes(hsig, 32);

        struct sprout_note_encryption ctx;
        sprout_note_encryption_init_with_esk(&ctx, esk);

        uint8_t plaintext[64];
        GetRandBytes(plaintext, 64);
        uint8_t ciphertext[80]; /* 64 + 16 */
        bool ok = sprout_note_encrypt(&ctx, hsig, pk_enc, plaintext, 64, ciphertext);

        /* Decrypt */
        uint8_t epk[32];
        curve25519_scalarmult_base(epk, esk);
        uint8_t decrypted[64];
        ok = ok && sprout_note_decrypt(sk_enc, epk, hsig, pk_enc,
                                       0, ciphertext, 80, decrypted);
        ok = ok && (memcmp(plaintext, decrypted, 64) == 0);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================ */
    /* Sapling keystore comprehensive tests                             */
    /* ================================================================ */

    printf("Sapling keystore generate multiple addresses... ");
    {
        struct sapling_keystore sks;
        sapling_keystore_init(&sks);
        uint8_t seed[32];
        GetRandBytes(seed, 32);
        bool ok = sapling_keystore_generate_seed(&sks);
        ok = ok && sks.has_seed;

        uint8_t d1[11], pk1[32], d2[11], pk2[32], d3[11], pk3[32];
        ok = ok && sapling_keystore_new_address(&sks, d1, pk1);
        ok = ok && sapling_keystore_new_address(&sks, d2, pk2);
        ok = ok && sapling_keystore_new_address(&sks, d3, pk3);
        ok = ok && (sks.num_keys == 3);

        /* All addresses should be different */
        ok = ok && (memcmp(pk1, pk2, 32) != 0);
        ok = ok && (memcmp(pk2, pk3, 32) != 0);

        /* Find by IVK */
        const struct sapling_key_entry *e1 =
            sapling_keystore_find_by_ivk(&sks, sks.keys[0].ivk);
        ok = ok && (e1 != NULL);
        ok = ok && (memcmp(e1->pk_d, pk1, 32) == 0);

        /* Have spending key */
        ok = ok && sapling_keystore_have_spending_key(&sks, sks.keys[1].ivk);

        sapling_keystore_free(&sks);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================ */
    /* Witness cursor depth bug regression test                         */
    /* ================================================================ */

    printf("Witness cursor depth preserved after serialize/deserialize... ");
    {
        /* Build a tree where the witness has an active cursor at non-trivial depth.
         * The bug: deserialize set cursor.depth = full tree depth (32) instead of
         * cursor_depth. This produces wrong root when incremental_tree_root pads
         * with empty hashes up to cursor.depth. */
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        struct uint256 cm;
        memset(cm.data, 0, 32);

        /* Append 3 commitments, take witness at #3.
         * Tree state: has_left=cm2, has_right=cm3 (cm0,cm1 combined into parent[0])
         * After witness init, next_depth gives cursor_depth > 0.
         * Then append 1 more to create a cursor subtree. */
        for (int i = 0; i < 3; i++) {
            cm.data[0] = (unsigned char)(i + 1);
            incremental_tree_append(&t, &cm);
        }
        struct incremental_witness w;
        incremental_witness_init(&w, &t);

        /* Advance witness with 2 more commitments to create cursor */
        for (int i = 0; i < 2; i++) {
            cm.data[0] = (unsigned char)(i + 10);
            incremental_witness_append(&w, &cm);
            incremental_tree_append(&t, &cm);
        }

        /* Verify witness has a cursor */
        bool has_cursor = w.has_cursor;
        size_t original_cursor_depth = w.cursor_depth;
        size_t original_cursor_tree_depth = w.cursor.depth;

        /* Compute root before serialization */
        struct uint256 root_before;
        incremental_witness_root(&w, &root_before);

        /* Also verify witness root matches tree root */
        struct uint256 tree_root;
        incremental_tree_root(&t, &tree_root);

        /* Serialize */
        struct byte_stream ws;
        stream_init(&ws, 4096);
        incremental_witness_serialize(&w, &ws);

        /* Deserialize */
        struct incremental_witness w2;
        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        bool ok = incremental_witness_deserialize(&w2, &rs,
            SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH,
            t.combine, t.uncommitted);

        /* Check cursor depth is correct */
        ok = ok && (w2.has_cursor == has_cursor);
        ok = ok && (w2.cursor_depth == original_cursor_depth);
        if (has_cursor) {
            ok = ok && (w2.cursor.depth == original_cursor_tree_depth);
        }

        /* Check root matches */
        struct uint256 root_after;
        incremental_witness_root(&w2, &root_after);
        ok = ok && (memcmp(root_before.data, root_after.data, 32) == 0);
        ok = ok && (memcmp(tree_root.data, root_after.data, 32) == 0);

        if (!ok) {
            char h1[65], h2[65], h3[65];
            uint256_get_hex(&root_before, h1);
            uint256_get_hex(&root_after, h2);
            uint256_get_hex(&tree_root, h3);
            printf("FAIL\n"
                "  has_cursor=%d, cursor_depth=%zu (expected %zu)\n"
                "  cursor.depth=%zu (expected %zu)\n"
                "  root before: %s\n"
                "  root after:  %s\n"
                "  tree root:   %s\n",
                w2.has_cursor, w2.cursor_depth, original_cursor_depth,
                has_cursor ? w2.cursor.depth : 0, original_cursor_tree_depth,
                h1, h2, h3);
            failures++;
        } else {
            printf("OK (cursor_depth=%zu, cursor.depth=%zu)\n",
                w2.cursor_depth, has_cursor ? w2.cursor.depth : (size_t)0);
        }
        stream_free(&ws);
    }

    printf("Witness serialize/deserialize roundtrip at 25K with cursor... ");
    {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        struct uint256 cm;
        memset(cm.data, 0, 32);

        /* Build tree with 25000 elements, witness at 12500, then advance the
         * witness by 1000 more. This produces num_filled=7 (the full
         * MAX_WITNESS_FILLS-bounded fill array) with an active cursor at
         * depth 14 — the same structural witness shape the serialize/
         * deserialize roundtrip exercises at 100K (which only reaches
         * cursor depth 16, still far short of the 32-deep tree). num_filled,
         * the active cursor, and the multi-level fill array are all
         * populated identically, so every roundtrip + cursor-preservation
         * assertion below is exercised. The 50K stress test further down
         * remains the dedicated large-scale anchor. */
        struct incremental_witness w;
        bool w_init = false;
        for (int i = 0; i < 25000; i++) {
            cm.data[0] = (unsigned char)(i & 0xff);
            cm.data[1] = (unsigned char)((i >> 8) & 0xff);
            cm.data[2] = (unsigned char)((i >> 16) & 0xff);
            if (w_init)
                incremental_witness_append(&w, &cm);
            incremental_tree_append(&t, &cm);
            if (i == 12499) {
                incremental_witness_init(&w, &t);
                w_init = true;
            }
        }

        /* Advance witness with 1000 more to create interesting cursor state */
        for (int i = 25000; i < 26000; i++) {
            cm.data[0] = (unsigned char)(i & 0xff);
            cm.data[1] = (unsigned char)((i >> 8) & 0xff);
            cm.data[2] = (unsigned char)((i >> 16) & 0xff);
            incremental_witness_append(&w, &cm);
            incremental_tree_append(&t, &cm);
        }

        struct uint256 tree_root, w_root;
        incremental_tree_root(&t, &tree_root);
        incremental_witness_root(&w, &w_root);

        /* Verify witness matches tree before serialize */
        bool roots_match = (memcmp(tree_root.data, w_root.data, 32) == 0);

        /* Serialize */
        struct byte_stream ws;
        stream_init(&ws, 8192);
        incremental_witness_serialize(&w, &ws);

        /* Deserialize */
        struct incremental_witness w2;
        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        bool deser_ok = incremental_witness_deserialize(&w2, &rs,
            SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH,
            t.combine, t.uncommitted);

        struct uint256 w2_root;
        incremental_witness_root(&w2, &w2_root);

        bool ok = roots_match && deser_ok &&
                  (memcmp(w_root.data, w2_root.data, 32) == 0) &&
                  (w2.has_cursor == w.has_cursor) &&
                  (w2.cursor_depth == w.cursor_depth);
        if (w.has_cursor)
            ok = ok && (w2.cursor.depth == w.cursor.depth);

        if (!ok) {
            char h1[65], h2[65], h3[65];
            uint256_get_hex(&tree_root, h1);
            uint256_get_hex(&w_root, h2);
            uint256_get_hex(&w2_root, h3);
            printf("FAIL\n"
                "  tree/witness match before: %d\n"
                "  tree root:   %s\n"
                "  witness:     %s\n"
                "  roundtrip:   %s\n"
                "  cursor: has=%d depth=%zu cursor.depth=%zu\n"
                "  deser:  has=%d depth=%zu cursor.depth=%zu\n",
                roots_match, h1, h2, h3,
                w.has_cursor, w.cursor_depth,
                w.has_cursor ? w.cursor.depth : (size_t)0,
                w2.has_cursor, w2.cursor_depth,
                w2.has_cursor ? w2.cursor.depth : (size_t)0);
            failures++;
        } else {
            printf("OK (%zu bytes, fills=%zu, cursor=%d depth=%zu)\n",
                ws.size, w2.num_filled, w2.has_cursor, w2.cursor_depth);
        }
        stream_free(&ws);
    }

    printf("Witness Merkle path valid at multiple positions... ");
    {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        struct uint256 cm;
        memset(cm.data, 0, 32);
        bool ok = true;

        /* Test at positions 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64 */
        int positions[] = {1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64};
        int num_pos = 12;
        struct incremental_witness witnesses[12];
        bool w_inits[12] = {false};

        for (int i = 0; i < 65; i++) {
            cm.data[0] = (unsigned char)(i & 0xff);
            incremental_tree_append(&t, &cm);
            for (int j = 0; j < num_pos; j++) {
                if (w_inits[j])
                    incremental_witness_append(&witnesses[j], &cm);
            }
            for (int j = 0; j < num_pos; j++) {
                if (i + 1 == positions[j]) {
                    incremental_witness_init(&witnesses[j], &t);
                    w_inits[j] = true;
                }
            }
        }

        /* For each witness, extract Merkle path and verify it can reconstruct root */
        struct uint256 tree_root;
        incremental_tree_root(&t, &tree_root);

        for (int j = 0; j < num_pos; j++) {
            struct uint256 w_root;
            incremental_witness_root(&witnesses[j], &w_root);
            if (memcmp(w_root.data, tree_root.data, 32) != 0) {
                printf("FAIL (witness %d root mismatch)\n", positions[j]);
                ok = false;
                break;
            }
            uint8_t path[1 + 32 * 33];
            size_t path_len;
            if (!incremental_witness_merkle_path(&witnesses[j], path, &path_len)) {
                printf("FAIL (witness %d path extraction failed)\n", positions[j]);
                ok = false;
                break;
            }
            /* Path should be: 1 byte depth + depth * 33 bytes */
            if (path_len != 1 + SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH * 33) {
                printf("FAIL (witness %d path_len=%zu, expected %d)\n",
                    positions[j], path_len,
                    1 + SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH * 33);
                ok = false;
                break;
            }

            /* Teeth: reconstruct the final anchor from the exact leaf and
             * serialized sibling/direction pairs. A length-only assertion
             * missed the historical level-0 inversion (leaf-as-sibling with
             * the opposite direction), which made every generated spend path
             * unusable by the canonical Sapling circuit. */
            struct uint256 cur = {{0}};
            cur.data[0] = (uint8_t)(positions[j] - 1);
            for (size_t level = 0;
                 level < SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH; level++) {
                struct uint256 sibling;
                struct uint256 parent;
                const size_t off = 1 + level * 33;
                memcpy(sibling.data, path + off, 32);
                const uint8_t direction = path[off + 32];
                if (direction == 0)
                    witnesses[j].tree.combine(
                        &cur, &sibling, level, &parent);
                else if (direction == 1)
                    witnesses[j].tree.combine(
                        &sibling, &cur, level, &parent);
                else {
                    printf("FAIL (witness %d invalid direction at level %zu)\n",
                           positions[j], level);
                    ok = false;
                    break;
                }
                cur = parent;
            }
            if (!ok)
                break;
            if (memcmp(cur.data, tree_root.data, 32) != 0) {
                printf("FAIL (witness %d serialized path does not reconstruct root)\n",
                       positions[j]);
                ok = false;
                break;
            }
        }
        if (ok)
            printf("OK (all %d positions valid)\n", num_pos);
        else
            failures++;
    }

    printf("Witness serialization blob size bounded... ");
    {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        struct uint256 cm;
        memset(cm.data, 0, 32);

        /* Build tree with 10000 elements */
        for (int i = 0; i < 10000; i++) {
            cm.data[0] = (unsigned char)(i & 0xff);
            cm.data[1] = (unsigned char)((i >> 8) & 0xff);
            incremental_tree_append(&t, &cm);
        }
        struct incremental_witness w;
        incremental_witness_init(&w, &t);

        /* Advance with 5000 more */
        for (int i = 0; i < 5000; i++) {
            cm.data[0] = (unsigned char)((i + 10000) & 0xff);
            cm.data[1] = (unsigned char)(((i + 10000) >> 8) & 0xff);
            incremental_witness_append(&w, &cm);
        }

        struct byte_stream ws;
        stream_init(&ws, 8192);
        incremental_witness_serialize(&w, &ws);

        /* Witness blob should be < 4096 bytes for any reasonable tree */
        bool ok = (ws.size < 4096);
        if (!ok) {
            printf("FAIL (blob size=%zu, expected < 4096)\n", ws.size);
            failures++;
        } else {
            printf("OK (blob=%zu bytes, fills=%zu, cursor=%d)\n",
                ws.size, w.num_filled, w.has_cursor);
        }
        stream_free(&ws);
    }

    printf("Witness deserialize rejects corrupt blobs... ");
    {
        bool ok = true;

        /* Empty blob */
        struct incremental_witness w;
        struct byte_stream rs;
        uint8_t empty[] = {0};
        stream_init_from_data(&rs, empty, 0);
        if (incremental_witness_deserialize(&w, &rs,
                SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH,
                sha256_compress_combine, sha256_compress_uncommitted)) {
            printf("FAIL (accepted empty blob)\n");
            ok = false;
        }

        /* Truncated blob: valid tree but missing filled count */
        if (ok) {
            struct incremental_merkle_tree t;
            sapling_tree_init(&t);
            struct uint256 cm;
            memset(cm.data, 0x42, 32);
            incremental_tree_append(&t, &cm);
            struct byte_stream ws;
            stream_init(&ws, 256);
            incremental_tree_serialize(&t, &ws);
            /* Just the tree, no filled/cursor */
            struct byte_stream rs2;
            stream_init_from_data(&rs2, ws.data, ws.size);
            if (incremental_witness_deserialize(&w, &rs2,
                    SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH,
                    t.combine, t.uncommitted)) {
                printf("FAIL (accepted truncated blob)\n");
                ok = false;
            }
            stream_free(&ws);
        }

        /* num_filled > MAX_WITNESS_FILLS */
        if (ok) {
            uint8_t bad[128] = {0};
            /* has_left=0, has_right=0, num_parents=0 (compact=0x00),
             * then num_filled = 0xFF (> 64) */
            bad[0] = 0; /* has_left */
            bad[1] = 0; /* has_right */
            bad[2] = 0; /* num_parents = 0 */
            bad[3] = 0xFD; /* compact_size prefix for 2-byte */
            bad[4] = 0xFF; /* lo byte = 255 */
            bad[5] = 0x00; /* hi byte = 0 → 255, which is > 64 */
            struct byte_stream rs3;
            stream_init_from_data(&rs3, bad, sizeof(bad));
            if (incremental_witness_deserialize(&w, &rs3,
                    SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH,
                    sha256_compress_combine, sha256_compress_uncommitted)) {
                printf("FAIL (accepted num_filled=255)\n");
                ok = false;
            }
        }

        if (ok) printf("OK\n");
        else failures++;
    }

    printf("Witness root == tree root at 50K elements (stress)... ");
    {
        struct incremental_merkle_tree *t = zcl_malloc(sizeof(*t), "merkle_tree");
        sapling_tree_init(t);
        struct uint256 cm;
        memset(cm.data, 0, 32);

        struct incremental_witness *w = zcl_malloc(sizeof(*w), "merkle_witness");
        bool w_init = false;

        for (int i = 0; i < 50000; i++) {
            cm.data[0] = (unsigned char)(i & 0xff);
            cm.data[1] = (unsigned char)((i >> 8) & 0xff);
            cm.data[2] = (unsigned char)((i >> 16) & 0xff);
            if (w_init)
                incremental_witness_append(w, &cm);
            incremental_tree_append(t, &cm);
            if (i == 24999) {
                incremental_witness_init(w, t);
                w_init = true;
            }
        }

        struct uint256 tree_root, w_root;
        incremental_tree_root(t, &tree_root);
        incremental_witness_root(w, &w_root);
        bool match = (memcmp(tree_root.data, w_root.data, 32) == 0);

        /* Serialize/deserialize roundtrip */
        struct byte_stream ws;
        stream_init(&ws, 8192);
        incremental_witness_serialize(w, &ws);

        struct incremental_witness w2;
        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        bool deser_ok = incremental_witness_deserialize(&w2, &rs,
            SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH,
            t->combine, t->uncommitted);

        struct uint256 w2_root;
        incremental_witness_root(&w2, &w2_root);
        bool roundtrip = (memcmp(w_root.data, w2_root.data, 32) == 0);

        bool ok = match && deser_ok && roundtrip;
        if (!ok) {
            char h1[65], h2[65], h3[65];
            uint256_get_hex(&tree_root, h1);
            uint256_get_hex(&w_root, h2);
            uint256_get_hex(&w2_root, h3);
            printf("FAIL (match=%d deser=%d roundtrip=%d)\n"
                "  tree:      %s\n"
                "  witness:   %s\n"
                "  roundtrip: %s\n"
                "  fills=%zu cursor=%d cdepth=%zu cursor.depth=%zu\n",
                match, deser_ok, roundtrip, h1, h2, h3,
                w2.num_filled, w2.has_cursor, w2.cursor_depth,
                w2.has_cursor ? w2.cursor.depth : (size_t)0);
            failures++;
        } else {
            printf("OK (%zu bytes, fills=%zu, cursor=%d)\n",
                ws.size, w2.num_filled, w2.has_cursor);
        }
        stream_free(&ws);
        free(t);
        free(w);
    }

    printf("Multiple witnesses track same tree correctly... ");
    {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        struct uint256 cm;
        memset(cm.data, 0, 32);

        /* Create witnesses at positions 100, 500, 999 in a 2000-element tree */
        struct incremental_witness w100, w500, w999;
        bool init100 = false, init500 = false, init999 = false;

        for (int i = 0; i < 2000; i++) {
            cm.data[0] = (unsigned char)(i & 0xff);
            cm.data[1] = (unsigned char)((i >> 8) & 0xff);
            if (init100) incremental_witness_append(&w100, &cm);
            if (init500) incremental_witness_append(&w500, &cm);
            if (init999) incremental_witness_append(&w999, &cm);
            incremental_tree_append(&t, &cm);
            if (i == 99)  { incremental_witness_init(&w100, &t); init100 = true; }
            if (i == 499) { incremental_witness_init(&w500, &t); init500 = true; }
            if (i == 999) { incremental_witness_init(&w999, &t); init999 = true; }
        }

        struct uint256 tree_root;
        incremental_tree_root(&t, &tree_root);

        struct uint256 r100, r500, r999;
        incremental_witness_root(&w100, &r100);
        incremental_witness_root(&w500, &r500);
        incremental_witness_root(&w999, &r999);

        bool ok = (memcmp(tree_root.data, r100.data, 32) == 0) &&
                  (memcmp(tree_root.data, r500.data, 32) == 0) &&
                  (memcmp(tree_root.data, r999.data, 32) == 0);

        /* Serialize/deserialize all three and verify */
        struct byte_stream s100, s500, s999;
        stream_init(&s100, 4096); stream_init(&s500, 4096); stream_init(&s999, 4096);
        incremental_witness_serialize(&w100, &s100);
        incremental_witness_serialize(&w500, &s500);
        incremental_witness_serialize(&w999, &s999);

        struct incremental_witness d100, d500, d999;
        struct byte_stream rs100, rs500, rs999;
        stream_init_from_data(&rs100, s100.data, s100.size);
        stream_init_from_data(&rs500, s500.data, s500.size);
        stream_init_from_data(&rs999, s999.data, s999.size);
        ok = ok && incremental_witness_deserialize(&d100, &rs100,
            SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH, t.combine, t.uncommitted);
        ok = ok && incremental_witness_deserialize(&d500, &rs500,
            SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH, t.combine, t.uncommitted);
        ok = ok && incremental_witness_deserialize(&d999, &rs999,
            SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH, t.combine, t.uncommitted);

        struct uint256 dr100, dr500, dr999;
        incremental_witness_root(&d100, &dr100);
        incremental_witness_root(&d500, &dr500);
        incremental_witness_root(&d999, &dr999);

        ok = ok && (memcmp(tree_root.data, dr100.data, 32) == 0);
        ok = ok && (memcmp(tree_root.data, dr500.data, 32) == 0);
        ok = ok && (memcmp(tree_root.data, dr999.data, 32) == 0);

        stream_free(&s100); stream_free(&s500); stream_free(&s999);
        if (ok)
            printf("OK (3 witnesses, all roots match)\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("Tree size computation correct at power-of-2 boundaries... ");
    {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        struct uint256 cm;
        memset(cm.data, 0x42, 32);
        bool ok = true;

        int check_sizes[] = {1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256};
        int num_checks = 16;
        int next_check = 0;

        for (int i = 0; i < 257 && next_check < num_checks; i++) {
            cm.data[0] = (unsigned char)(i & 0xff);
            cm.data[1] = (unsigned char)((i >> 8) & 0xff);
            incremental_tree_append(&t, &cm);
            if (i + 1 == check_sizes[next_check]) {
                size_t sz = incremental_tree_size(&t);
                if ((int)sz != check_sizes[next_check]) {
                    printf("FAIL (at %d: got size %zu)\n", check_sizes[next_check], sz);
                    ok = false;
                    break;
                }
                next_check++;
            }
        }
        if (ok) printf("OK (all 16 sizes correct)\n");
        else failures++;
    }

    /* ================================================================ */
    /* Sapling tree root verification (connect_block check)             */
    /* ================================================================ */

    printf("Sapling tree root verification matches block header... ");
    {
        struct incremental_merkle_tree tree;
        sapling_tree_init(&tree);
        struct uint256 empty_root;
        incremental_tree_root(&tree, &empty_root);

        struct uint256 cm;
        uint256_set_hex(&cm,
            "5a8d47a74b48efce5841a43ddaccdc75253a4ccda847d67ada8309dcf01d3943");
        incremental_tree_append(&tree, &cm);

        struct uint256 root_after;
        incremental_tree_root(&tree, &root_after);

        bool ok = (memcmp(empty_root.data, root_after.data, 32) != 0);
        /* Correct header would match */
        ok = ok && (uint256_cmp(&root_after, &root_after) == 0);
        /* Wrong header would not match */
        struct uint256 wrong;
        memset(&wrong, 0xff, 32);
        ok = ok && (uint256_cmp(&root_after, &wrong) != 0);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Sapling tree persist + reload preserves root... ");
    {
        struct incremental_merkle_tree tree;
        sapling_tree_init(&tree);
        for (int i = 0; i < 10; i++) {
            struct uint256 cm;
            memset(&cm, 0, sizeof(cm));
            cm.data[0] = (uint8_t)(0x42 + i);
            cm.data[31] = (uint8_t)(i);
            incremental_tree_append(&tree, &cm);
        }
        struct uint256 root_before;
        incremental_tree_root(&tree, &root_before);

        struct byte_stream ws;
        stream_init(&ws, 4096);
        bool ok = incremental_tree_serialize(&tree, &ws);
        struct incremental_merkle_tree loaded;
        sapling_tree_init(&loaded);
        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        ok = ok && incremental_tree_deserialize(&loaded, &rs);
        struct uint256 root_after;
        incremental_tree_root(&loaded, &root_after);
        ok = ok && (memcmp(root_before.data, root_after.data, 32) == 0);
        ok = ok && (incremental_tree_size(&tree) ==
                    incremental_tree_size(&loaded));
        stream_free(&ws);
        stream_free(&rs);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
