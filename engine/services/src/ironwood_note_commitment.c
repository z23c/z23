/* purpose: Evaluate prepared public Ironwood V3 note commitment inputs. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_note_commitment.h"
#include "services/ironwood_merkle_crh.h"
#include "services/ironwood_resident_params.h"
#include "ironwood_pasta_internal.h"
#include "ironwood_sinsemilla_internal.h"
#include "base/serialize_le.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string.h>

/* Orchard 0.16.0 / sinsemilla 0.2.0 NoteCommit-M and NoteCommit-r. */
static const uint8_t note_q[32] = {
    0x5d,0x74,0xa8,0x40,0x09,0xba,0x0e,0x32,0x2a,0xdd,0x46,0xfd,0x5a,0x0f,0x96,0xc5,
    0x5d,0xed,0xb0,0x79,0xb4,0xf2,0x9f,0xf7,0x0d,0xcd,0xfb,0x56,0xa0,0x07,0x80,0x97
};
static const uint8_t note_r[32] = {
    0x13,0x6e,0xfc,0x0f,0x48,0x2c,0x02,0x2c,0x7c,0xa4,0x14,0xfc,0x5c,0xc5,0x9e,0x23,
    0xf2,0x3d,0x6f,0x93,0xab,0x9f,0x23,0xcd,0x33,0x45,0xa9,0x28,0xc3,0x06,0xb2,0xa6
};

static void append_bits(uint8_t *dst, size_t *offset, const uint8_t *src, size_t count)
{
    for (size_t i = 0; i < count; ++i, ++*offset)
        dst[*offset / 8] |= (uint8_t)(((src[i / 8] >> (i % 8)) & 1u) << (*offset % 8));
}
static void note_pieces(const struct ironwood_note_commitment_public *in, uint16_t pieces[109])
{
    uint8_t bits[137] = {0}, value[8];
    size_t offset = 0;
    zcl_write_u64_le(value, in->value);
    append_bits(bits, &offset, in->gd, 256);
    append_bits(bits, &offset, in->pkd, 256);
    append_bits(bits, &offset, value, 64);
    append_bits(bits, &offset, in->rho, 255);
    append_bits(bits, &offset, in->psi, 255);
    for (size_t i = 0; i < 109; ++i) {
        unsigned v = 0;
        for (size_t j = 0; j < 10; ++j) {
            size_t b = i * 10 + j;
            v |= ((bits[b / 8] >> (b % 8)) & 1u) << j;
        }
        pieces[i] = (uint16_t)v;
    }
}

struct note_work {
    BN_CTX *ctx;
    EC_GROUP *pallas, *vesta;
    EC_POINT *gd, *pkd, *acc, *r, *blind;
    BIGNUM *scalar, *order, *x;
};
static void note_work_free(struct note_work *w)
{
    BN_free(w->x); BN_free(w->order); BN_free(w->scalar);
    EC_POINT_free(w->blind); EC_POINT_free(w->r); EC_POINT_free(w->acc);
    EC_POINT_free(w->pkd); EC_POINT_free(w->gd);
    EC_GROUP_free(w->vesta); EC_GROUP_free(w->pallas); BN_CTX_free(w->ctx);
}
static bool note_work_init(struct note_work *w, const struct ironwood_note_commitment_public *in)
{
    w->ctx = BN_CTX_new();
    if (!w->ctx || !ironwood_pasta_group(IRONWOOD_PALLAS, w->ctx, &w->pallas).ok ||
        !ironwood_pasta_group(IRONWOOD_VESTA, w->ctx, &w->vesta).ok) return false;
    w->gd = EC_POINT_new(w->pallas); w->pkd = EC_POINT_new(w->pallas);
    w->acc = EC_POINT_new(w->pallas); w->r = EC_POINT_new(w->pallas);
    w->blind = EC_POINT_new(w->pallas);
    w->scalar = BN_lebin2bn(in->rcm, 32, NULL); w->order = BN_new(); w->x = BN_new();
    return w->gd && w->pkd && w->acc && w->r && w->blind && w->scalar && w->order && w->x &&
        EC_GROUP_get_curve(w->vesta, w->order, NULL, NULL, w->ctx) == 1 &&
        BN_cmp(w->scalar, w->order) < 0;
}
static bool note_compute(struct note_work *w, const struct ironwood_note_commitment_public *in,
                         const uint8_t *parameters, uint8_t out[32])
{
    if (!ironwood_pasta_decode(in->gd, IRONWOOD_PALLAS, false, w->pallas, w->gd, w->ctx).ok ||
        !ironwood_pasta_decode(in->pkd, IRONWOOD_PALLAS, false, w->pallas, w->pkd, w->ctx).ok ||
        !ironwood_pasta_decode(note_r, IRONWOOD_PALLAS, false, w->pallas, w->r, w->ctx).ok) return false;
    uint16_t pieces[109];
    note_pieces(in, pieces);
    if (ironwood_sinsemilla_hash_points(w->pallas, w->ctx, w->acc, parameters, note_q, pieces, 109) != ADD_OK ||
        EC_POINT_mul(w->pallas, w->blind, NULL, w->r, w->scalar, w->ctx) != 1 ||
        EC_POINT_add(w->pallas, w->acc, w->acc, w->blind, w->ctx) != 1) return false;
    int infinity = EC_POINT_is_at_infinity(w->pallas, w->acc);
    if (infinity < 0) return false;
    if (infinity) { memset(out, 0, 32); return true; }
    return EC_POINT_get_affine_coordinates(w->pallas, w->acc, w->x, NULL, w->ctx) == 1 &&
        BN_bn2lebinpad(w->x, out, 32) == 32;
}
struct zcl_result ironwood_note_commitment_compute_public(
    const struct ironwood_note_commitment_public *in, uint8_t out[32])
{
    if (!in || !out || !ironwood_pasta_fp_canonical(in->rho).ok || !ironwood_pasta_fp_canonical(in->psi).ok)
        return ZCL_ERR(-1, "Invalid public note commitment input");
    size_t size = 0;
    const uint8_t *parameters = ironwood_resident_merkle_parameters(&size);
    if (!ironwood_merkle_parameters_validate(parameters, size).ok)
        return ZCL_ERR(-1, "Invalid note commitment table");
    struct note_work w = {0};
    uint8_t result[32];
    bool ok = note_work_init(&w, in) && note_compute(&w, in, parameters, result);
    note_work_free(&w);
    if (!ok) return ZCL_ERR(-1, "Cannot evaluate public note commitment");
    memcpy(out, result, sizeof result);
    return ZCL_OK;
}
