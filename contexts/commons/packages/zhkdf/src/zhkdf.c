#include "zhkdf/zhkdf.h"

#include <zsha256/zsha256.h>

int zhkdf_sha256_extract(const void *salt, size_t salt_len,
                         const void *ikm, size_t ikm_len,
                         uint8_t prk[ZHKDF_SHA256_PRK_LEN])
{
    uint8_t zero_salt[ZSHA256_DIGEST_LEN] = {0};

    if (!ikm || !prk)
        return -1;
    if (!salt || salt_len == 0) {
        salt = zero_salt;
        salt_len = sizeof zero_salt;
    }
    zsha256_hmac(salt, salt_len, ikm, ikm_len, prk);
    return 0;
}

int zhkdf_sha256_expand(const uint8_t prk[ZHKDF_SHA256_PRK_LEN],
                        const void *info, size_t info_len,
                        uint8_t *okm, size_t okm_len)
{
    zsha256_hmac_ctx ctx;
    uint8_t t[ZSHA256_DIGEST_LEN];
    size_t t_len = 0;      /* length of previous T block (0 for T(1)) */
    size_t done = 0;
    unsigned counter = 1;

    if (!prk || !okm || okm_len == 0 || okm_len > ZHKDF_SHA256_MAX_OKM_LEN)
        return -1;
    if (!info)
        info_len = 0;

    while (done < okm_len) {
        size_t take;

        zsha256_hmac_init(&ctx, prk, ZHKDF_SHA256_PRK_LEN);
        if (t_len)
            zsha256_hmac_update(&ctx, t, t_len);
        if (info_len)
            zsha256_hmac_update(&ctx, info, info_len);
        zsha256_hmac_update(&ctx, &(const uint8_t){(uint8_t)counter}, 1);
        zsha256_hmac_final(&ctx, t);
        t_len = sizeof t;

        take = okm_len - done;
        if (take > sizeof t)
            take = sizeof t;
        for (size_t i = 0; i < take; i++)
            okm[done + i] = t[i];
        done += take;
        counter++;
    }
    return 0;
}

int zhkdf_sha256(const void *salt, size_t salt_len,
                 const void *ikm, size_t ikm_len,
                 const void *info, size_t info_len,
                 uint8_t *okm, size_t okm_len)
{
    uint8_t prk[ZHKDF_SHA256_PRK_LEN];

    if (zhkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk) != 0)
        return -1;
    return zhkdf_sha256_expand(prk, info, info_len, okm, okm_len);
}
