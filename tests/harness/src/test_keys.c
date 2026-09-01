/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "keys/key_io.h"

int test_keys(void)
{
    int failures = 0;

    printf("pubkey init/validate... ");
    {
        struct pubkey pk;
        pubkey_init(&pk);
        if (!pubkey_is_valid(&pk))
            printf("OK (empty key is invalid)\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("pubkey_get_id... ");
    {
        unsigned char data[33];
        memset(data, 0, 33);
        data[0] = 0x02;
        data[1] = 0x79; data[2] = 0xBE; data[3] = 0x66; data[4] = 0x7E;
        struct pubkey pk;
        pubkey_set(&pk, data, 33);
        struct key_id kid = pubkey_get_id(&pk);
        if (!uint160_is_null(&kid.id))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("ext_pubkey encode/decode... ");
    {
        struct ext_pubkey epk;
        memset(&epk, 0, sizeof(epk));
        epk.nDepth = 3;
        epk.nChild = 42;
        unsigned char data[33];
        memset(data, 0, 33);
        data[0] = 0x02;
        data[1] = 0x01;
        pubkey_set(&epk.pubkey, data, 33);

        unsigned char code[BIP32_EXTKEY_SIZE];
        bool encoded = ext_pubkey_encode(&epk, code);

        struct ext_pubkey decoded;
        ext_pubkey_decode(&decoded, code);

        if (encoded && decoded.nDepth == 3 && decoded.nChild == 42 &&
            decoded.pubkey.size == 33)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("key generate + sign + verify... ");
    {
        struct privkey k;
        privkey_make_new(&k, true);
        struct pubkey pk;
        privkey_get_pubkey(&k, &pk);

        struct uint256 hash;
        memset(hash.data, 0x42, 32);

        unsigned char sig[SIGNATURE_SIZE];
        size_t siglen = SIGNATURE_SIZE;
        bool signed_ok = privkey_sign(&k, &hash, sig, &siglen);
        bool verified = pubkey_verify(&pk, &hash, sig, siglen);

        if (signed_ok && verified)
            printf("OK\n");
        else {
            printf("FAIL (signed=%d, verified=%d)\n", signed_ok, verified);
            failures++;
        }
    }

    printf("key sign_compact + recover... ");
    {
        struct privkey k;
        privkey_make_new(&k, true);
        struct pubkey pk;
        privkey_get_pubkey(&k, &pk);

        struct uint256 hash;
        memset(hash.data, 0xAB, 32);

        unsigned char csig[COMPACT_SIGNATURE_SIZE];
        bool signed_ok = privkey_sign_compact(&k, &hash, csig);

        struct pubkey recovered;
        bool recovered_ok = pubkey_recover_compact(&recovered, &hash, csig);

        if (signed_ok && recovered_ok &&
            recovered.size == pk.size &&
            memcmp(recovered.vch, pk.vch, pk.size) == 0)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("encode_destination pubkey... ");
    {
        const unsigned char pubkey_pfx[] = {0x1C, 0xB8};
        const unsigned char script_pfx[] = {0x1C, 0xBD};
        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        memset(dest.id.key.id.data, 0x01, 20);
        char addr[64];
        if (encode_destination(&dest, pubkey_pfx, 2, script_pfx, 2, addr, sizeof(addr)) &&
            strlen(addr) > 20) {
            struct tx_destination decoded;
            if (decode_destination(addr, pubkey_pfx, 2, script_pfx, 2, &decoded) &&
                decoded.type == DEST_KEY_ID &&
                memcmp(decoded.id.key.id.data, dest.id.key.id.data, 20) == 0)
                printf("OK\n");
            else { printf("FAIL (decode mismatch)\n"); failures++; }
        } else { printf("FAIL (encode)\n"); failures++; }
    }

    printf("encode_destination script... ");
    {
        const unsigned char pubkey_pfx[] = {0x1C, 0xB8};
        const unsigned char script_pfx[] = {0x1C, 0xBD};
        struct tx_destination dest;
        dest.type = DEST_SCRIPT_ID;
        memset(dest.id.script.hash.data, 0xAB, 20);
        char addr[64];
        if (encode_destination(&dest, pubkey_pfx, 2, script_pfx, 2, addr, sizeof(addr))) {
            struct tx_destination decoded;
            if (decode_destination(addr, pubkey_pfx, 2, script_pfx, 2, &decoded) &&
                decoded.type == DEST_SCRIPT_ID &&
                memcmp(decoded.id.script.hash.data, dest.id.script.hash.data, 20) == 0)
                printf("OK\n");
            else { printf("FAIL (decode mismatch)\n"); failures++; }
        } else { printf("FAIL (encode)\n"); failures++; }
    }

    printf("encode/decode_secret roundtrip... ");
    {
        const unsigned char secret_pfx[] = {0x80};
        struct privkey key;
        privkey_init(&key);
        memset(key.vch, 0x42, 32);
        key.fValid = true;
        key.fCompressed = true;
        char wif[64];
        if (encode_secret(&key, secret_pfx, 1, wif, sizeof(wif))) {
            struct privkey decoded;
            if (decode_secret(wif, secret_pfx, 1, &decoded) &&
                decoded.fCompressed == true &&
                memcmp(decoded.vch, key.vch, 32) == 0)
                printf("OK\n");
            else { printf("FAIL (decode mismatch)\n"); failures++; }
        } else { printf("FAIL (encode)\n"); failures++; }
    }

    printf("decode_destination invalid... ");
    {
        const unsigned char pubkey_pfx[] = {0x1C, 0xB8};
        const unsigned char script_pfx[] = {0x1C, 0xBD};
        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        if (!decode_destination("1invalidaddress", pubkey_pfx, 2, script_pfx, 2, &dest))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
