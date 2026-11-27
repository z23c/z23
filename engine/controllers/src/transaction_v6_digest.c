/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Compute ZIP 229 digests from checked v6 transaction views.
 */
#include "controllers/transaction_v6_digest.h"
#include "crypto/blake2b.h"
#include "base/serialize_le.h"
#include <string.h>

/* Widths and offsets below follow the v6 serialized field order in ZIP 229. */
enum { HASH = 32, HEADER = 20, PREVOUT = 36, SEQUENCE = 4, AMOUNT = 8,
       SAPLING_SPEND = 96, SAPLING_OUTPUT = 756, ACTION = 820,
       PROOF = 192, SIGNATURE = 64, ENC_PREFIX = 116, MEMO = 512 };
struct reader { const uint8_t *p; size_t n; };
struct digest_pair { uint8_t effect[HASH], auth[HASH]; };
#define CHECK(x) do { if (!(x)) return false; } while (0)
static bool take(struct reader *r, uint64_t count, size_t width, const uint8_t **out)
{
    if (!width || count > r->n / width) return false;
    size_t n = (size_t)count * width;
    *out = r->p; r->p += n; r->n -= n;
    return true;
}
static bool compact(struct reader *r, uint64_t *value)
{
    const uint8_t *p;
    CHECK(take(r, 1, 1, &p));
    if (*p < 253) { *value = *p; return true; }
    size_t width = (size_t)1 << (*p - 252);
    CHECK(take(r, width, 1, &p));
    uint64_t v = width == 2 ? zcl_read_u16_le(p) :
                 width == 4 ? zcl_read_u32_le(p) : zcl_read_u64_le(p);
    uint64_t minimum = width == 2 ? 253 : width == 4 ? 65536 : UINT64_C(4294967296);
    if (v < minimum) return false;
    *value = v; return true;
}
static bool start(struct blake2b_ctx *h, const char name[16])
{ return blake2b_init_salt_personal(h, HASH, NULL, 0, NULL, (const uint8_t *)name) == 0; }
static bool add(struct blake2b_ctx *h, const void *p, size_t n)
{ return !n || blake2b_update(h, p, n) == 0; }
static bool finish(struct blake2b_ctx *h, uint8_t out[HASH])
{ return blake2b_final(h, out, HASH) == 0; }
static bool child(struct blake2b_ctx *parent, struct blake2b_ctx *nested)
{
    uint8_t out[HASH];
    return finish(nested, out) && add(parent, out, sizeof out);
}
static bool script(struct reader *r)
{
    uint64_t n; const uint8_t *p;
    return compact(r, &n) && take(r, n, 1, &p);
}
static bool transparent(const struct v6_wire_view *v, struct digest_pair *out)
{
    struct blake2b_ctx tx, auth, prev, seq, outputs;
    CHECK(start(&tx, "ZTxIdTranspaHash")); CHECK(start(&auth, "ZTxAuthTransHash"));
    CHECK(start(&prev, "ZTxIdPrevoutHash")); CHECK(start(&seq, "ZTxIdSequencHash"));
    CHECK(start(&outputs, "ZTxIdOutputsHash"));
    struct v6_wire_cursor cursor; struct v6_span item;
    CHECK(v6_wire_cursor_init(v, true, &cursor));
    while (cursor.count) {
        CHECK(v6_wire_cursor_next(&cursor, &item));
        struct reader r = {item.data, item.size}; const uint8_t *p;
        CHECK(take(&r, PREVOUT, 1, &p)); CHECK(add(&prev, p, PREVOUT));
        p = r.p; CHECK(script(&r)); CHECK(add(&auth, p, (size_t)(r.p - p)));
        CHECK(take(&r, SEQUENCE, 1, &p)); CHECK(add(&seq, p, SEQUENCE));
        if (r.n) return false;
    }
    CHECK(v6_wire_cursor_init(v, false, &cursor));
    while (cursor.count) {
        CHECK(v6_wire_cursor_next(&cursor, &item));
        CHECK(add(&outputs, item.data, item.size));
    }
    if (v->inputs || v->outputs) {
        CHECK(child(&tx, &prev)); CHECK(child(&tx, &seq)); CHECK(child(&tx, &outputs));
    }
    return finish(&tx, out->effect) && finish(&auth, out->auth);
}
static bool sapling(const struct v6_wire_view *v, struct digest_pair *out)
{
    struct blake2b_ctx tx, auth, spends, outputs, cs, os, co, memo, oo;
    CHECK(start(&tx,"ZTxIdSaplingHash")); CHECK(start(&auth,"ZTxAuthSapliH_v6"));
    CHECK(start(&spends,"ZTxIdSSpendsHash")); CHECK(start(&outputs,"ZTxIdSOutputHash"));
    CHECK(start(&cs,"ZTxIdSSpendCHash")); CHECK(start(&os,"ZTxIdSSpendNH_v6"));
    struct reader sr = {v->sapling_spends.wire.data, v->sapling_spends.wire.size};
    const uint8_t *p;
    for (uint64_t i = 0; i < v->sapling_spends.count; ++i) {
        CHECK(take(&sr, SAPLING_SPEND, 1, &p));
        /* spend = cv, nullifier, rk */
        CHECK(add(&cs,p+HASH,HASH)); CHECK(add(&os,p,HASH)); CHECK(add(&os,p+2*HASH,HASH));
    }
    if (sr.n) return false;
    if (v->sapling_spends.count) { CHECK(child(&spends,&cs)); CHECK(child(&spends,&os)); }
    CHECK(start(&co,"ZTxIdSOutC__Hash")); CHECK(start(&memo,"ZTxIdSOutM__Hash"));
    CHECK(start(&oo,"ZTxIdSOutN__Hash"));
    struct reader or = {v->sapling_outputs.wire.data, v->sapling_outputs.wire.size};
    for (uint64_t i = 0; i < v->sapling_outputs.count; ++i) {
        CHECK(take(&or,SAPLING_OUTPUT,1,&p));
        /* output = cv, cmu, ephemeral key, encrypted note and outgoing ciphertext */
        CHECK(add(&co,p+HASH,ENC_PREFIX)); CHECK(add(&memo,p+HASH+ENC_PREFIX,MEMO));
        CHECK(add(&oo,p,HASH)); CHECK(add(&oo,p+HASH+ENC_PREFIX+MEMO,96));
    }
    if (or.n) return false;
    if (v->sapling_outputs.count) { CHECK(child(&outputs,&co)); CHECK(child(&outputs,&memo)); CHECK(child(&outputs,&oo)); }
    if (v->sapling_spends.count || v->sapling_outputs.count) {
        struct reader tail = {v->sapling_tail.data, v->sapling_tail.size};
        CHECK(child(&tx,&spends)); CHECK(child(&tx,&outputs));
        CHECK(take(&tail,AMOUNT,1,&p)); CHECK(add(&tx,p,AMOUNT));
        const uint8_t *anchor = NULL;
        if (v->sapling_spends.count) CHECK(take(&tail,HASH,1,&anchor));
        p = tail.p;
        const uint8_t *unused;
        CHECK(take(&tail,v->sapling_spends.count,PROOF,&unused));
        CHECK(take(&tail,v->sapling_spends.count,SIGNATURE,&unused));
        CHECK(take(&tail,v->sapling_outputs.count,PROOF,&unused));
        CHECK(take(&tail,SIGNATURE,1,&unused));
        CHECK(add(&auth,p,(size_t)(tail.p-p)));
        if (anchor) CHECK(add(&auth,anchor,HASH));
        if (tail.n) return false;
    }
    return finish(&tx,out->effect) && finish(&auth,out->auth);
}
static const char orchard_names[5][17] = {"ZTxIdOrchardH_v6","ZTxAuthOrchaH_v6","ZTxIdOrcActCHash","ZTxIdOrcActMHash","ZTxIdOrcActNHash"};
static const char ironwood_names[5][17] = {"ZTxIdIronwd_H_v6","ZTxAuthIrnwdH_v6","ZTxIdIrnActCH_v6","ZTxIdIrnActMH_v6","ZTxIdIrnActNH_v6"};
static bool actions(const struct v6_bundle *bundle, const char names[5][17],
                    uint8_t mask, struct digest_pair *out)
{
    struct blake2b_ctx tx, auth, compact_hash, memo, other;
    CHECK(start(&tx,names[0])); CHECK(start(&auth,names[1]));
    CHECK(start(&compact_hash,names[2])); CHECK(start(&memo,names[3])); CHECK(start(&other,names[4]));
    struct reader r = {bundle->wire.data,bundle->wire.size};
    uint64_t count; const uint8_t *p;
    CHECK(compact(&r,&count)); if (count != bundle->count) return false;
    for (uint64_t i = 0; i < count; ++i) {
        CHECK(take(&r,ACTION,1,&p));
        /* action = cv, nullifier, rk, cmx, ephemeral key, ciphertexts */
        CHECK(add(&compact_hash,p+HASH,HASH));
        CHECK(add(&compact_hash,p+3*HASH,ENC_PREFIX));
        CHECK(add(&memo,p+3*HASH+ENC_PREFIX,MEMO));
        CHECK(add(&other,p,HASH)); CHECK(add(&other,p+2*HASH,HASH));
        CHECK(add(&other,p+3*HASH+ENC_PREFIX+MEMO,96));
    }
    if (count) {
        CHECK(child(&tx,&compact_hash)); CHECK(child(&tx,&memo)); CHECK(child(&tx,&other));
        CHECK(take(&r,1+AMOUNT,1,&p));
        if (p[0] & (uint8_t)~mask) return false;
        CHECK(add(&tx,p,1+AMOUNT));
        const uint8_t *anchor; CHECK(take(&r,HASH,1,&anchor));
        uint64_t proof; CHECK(compact(&r,&proof));
        CHECK(take(&r,proof,1,&p));
        const uint8_t *unused;
        CHECK(take(&r,count,SIGNATURE,&unused)); CHECK(take(&r,SIGNATURE,1,&unused));
        CHECK(add(&auth,p,(size_t)(r.p-p))); CHECK(add(&auth,anchor,HASH));
    }
    if (r.n) return false;
    return finish(&tx,out->effect) && finish(&auth,out->auth);
}
bool v6_wire_digests(const struct v6_wire_view *v, struct v6_digests *result)
{
    if (!result) return false;
    memset(result,0,sizeof(*result));
    if (!v || !v->header.data || v->header.size != HEADER) return false;
    struct digest_pair pools[4];
    CHECK(transparent(v,&pools[0])); CHECK(sapling(v,&pools[1]));
    CHECK(actions(&v->orchard,orchard_names,3,&pools[2]));
    CHECK(actions(&v->ironwood,ironwood_names,7,&pools[3]));
    struct blake2b_ctx header, tx, auth;
    char tx_name[16] = "ZcashTxHash_", auth_name[16] = "ZTxAuthHash_";
    /* Header bytes 8..11 carry the branch identifier in wire byte order. */
    memcpy(tx_name+12,v->header.data+8,4); memcpy(auth_name+12,v->header.data+8,4);
    CHECK(start(&header,"ZTxIdHeadersHash")); CHECK(add(&header,v->header.data,HEADER));
    CHECK(start(&tx,tx_name)); CHECK(start(&auth,auth_name)); CHECK(child(&tx,&header));
    for (size_t i = 0; i < 4; ++i) {
        CHECK(add(&tx,pools[i].effect,HASH)); CHECK(add(&auth,pools[i].auth,HASH));
    }
    struct v6_digests value;
    CHECK(finish(&tx,value.txid)); CHECK(finish(&auth,value.auth));
    memcpy(value.sapling_effect,pools[1].effect,HASH); memcpy(value.sapling_auth,pools[1].auth,HASH);
    memcpy(value.orchard_effect,pools[2].effect,HASH); memcpy(value.orchard_auth,pools[2].auth,HASH);
    memcpy(value.ironwood_effect,pools[3].effect,HASH); memcpy(value.ironwood_auth,pools[3].auth,HASH);
    *result = value; return true;
}
