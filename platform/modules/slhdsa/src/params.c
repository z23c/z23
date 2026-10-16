/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: SLH-DSA-SHAKE parameter table (FIPS 205 Table 2). */

#include "slhdsa_internal.h"

#define SLH_PARAMS(n_, h_, d_, a_, k_, m_)                                   \
    {                                                                        \
        .n = (n_), .h = (h_), .d = (d_), .hp = (h_) / (d_), .a = (a_),       \
        .k = (k_), .len = 2 * (n_) + SLH_LEN2, .m = (m_),                    \
        .fors_size = (size_t)(k_) * ((a_) + 1) * (n_),                       \
        .xmss_size = (size_t)(2 * (n_) + SLH_LEN2 + (h_) / (d_)) * (n_),     \
        .sig_size = (size_t)(n_) + (size_t)(k_) * ((a_) + 1) * (n_) +        \
                    (size_t)(d_) * (2 * (n_) + SLH_LEN2 + (h_) / (d_)) * (n_)\
    }

static const struct slh_params table[] = {
    [ZCL_SLHDSA_SHAKE_128S] = SLH_PARAMS(16, 63, 7, 12, 14, 30),
    [ZCL_SLHDSA_SHAKE_192S] = SLH_PARAMS(24, 63, 7, 14, 17, 39),
};

const struct slh_params *slh_params_get(enum zcl_slhdsa_param param)
{
    if ((unsigned)param >= sizeof(table) / sizeof(table[0]))
        return nullptr;
    return &table[param];
}

size_t zcl_slhdsa_public_key_size(enum zcl_slhdsa_param param)
{
    const struct slh_params *p = slh_params_get(param);
    return p ? 2u * p->n : 0;
}

size_t zcl_slhdsa_secret_key_size(enum zcl_slhdsa_param param)
{
    const struct slh_params *p = slh_params_get(param);
    return p ? 4u * p->n : 0;
}

size_t zcl_slhdsa_signature_size(enum zcl_slhdsa_param param)
{
    const struct slh_params *p = slh_params_get(param);
    return p ? p->sig_size : 0;
}
