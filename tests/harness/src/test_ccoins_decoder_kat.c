/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "coins/coins.h"
#include "coins/compressor.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "services/utxo_import_pipeline.h"
#include "storage/chainstate_legacy_reader.h"
#include "storage/coins_db.h"
#include "storage/dbwrapper.h"

#include <stdio.h>
#include <string.h>

struct expected_out {
    uint32_t vout;
    int64_t value;
    uint16_t script_len;
    uint8_t script[80];
};

struct ccoins_case {
    const char *name;
    bool coinbase;
    int version;
    int height;
    uint8_t txid_seed;
    const uint8_t *masks;
    size_t mask_count;
    unsigned int nonzero_masks;
    const struct expected_out *outs;
    size_t out_count;
};

struct legacy_capture {
    struct expected_out outs[16];
    size_t out_count;
    int height;
    int version;
    bool coinbase;
    bool txid_ok;
};

static const uint8_t g_secp256k1_x[32] = {
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
};

static void fill_txid(struct uint256 *txid, uint8_t seed)
{
    for (size_t i = 0; i < sizeof(txid->data); i++)
        txid->data[i] = (uint8_t)(seed + i);
}

static bool expected_from_special(struct expected_out *out, uint32_t vout,
                                  int64_t value, uint8_t nsize,
                                  uint8_t salt)
{
    uint8_t raw[32];
    size_t raw_len = script_compress_special_size(nsize);
    if (raw_len == 0 || raw_len > sizeof(raw))
        return false;

    if (nsize >= 2)
        memcpy(raw, g_secp256k1_x, sizeof(g_secp256k1_x));
    else {
        for (size_t i = 0; i < raw_len; i++)
            raw[i] = (uint8_t)(salt + i);
    }

    struct script sc;
    script_init(&sc);
    if (!script_decompress(&sc, nsize, raw, raw_len))
        return false;
    if (sc.size > sizeof(out->script))
        return false;

    memset(out, 0, sizeof(*out));
    out->vout = vout;
    out->value = value;
    out->script_len = (uint16_t)sc.size;
    memcpy(out->script, sc.data, sc.size);
    return true;
}

static bool expected_from_raw(struct expected_out *out, uint32_t vout,
                              int64_t value)
{
    static const uint8_t raw_script[] = {
        OP_RETURN, 0x04, 'z', 'c', 'l', '2',
    };
    if (sizeof(raw_script) > sizeof(out->script))
        return false;
    memset(out, 0, sizeof(*out));
    out->vout = vout;
    out->value = value;
    out->script_len = (uint16_t)sizeof(raw_script);
    memcpy(out->script, raw_script, sizeof(raw_script));
    return true;
}

static bool append_expected_txout(struct byte_stream *s,
                                  const struct expected_out *out,
                                  uint8_t nsize)
{
    bool ok = true;
    ok &= stream_write_varint(s, compress_amount((uint64_t)out->value));
    if (nsize < 6) {
        size_t raw_len = script_compress_special_size(nsize);
        uint8_t raw[32];
        if (raw_len == 0 || raw_len > sizeof(raw))
            return false;
        if (nsize >= 2)
            memcpy(raw, g_secp256k1_x, sizeof(g_secp256k1_x));
        else {
            const uint8_t *src = (nsize == 0) ? out->script + 3
                                              : out->script + 2;
            memcpy(raw, src, raw_len);
        }
        ok &= stream_write_varint(s, nsize);
        ok &= stream_write_bytes(s, raw, raw_len);
    } else {
        ok &= stream_write_varint(s, (uint64_t)out->script_len + 6u);
        ok &= stream_write_bytes(s, out->script, out->script_len);
    }
    return ok && !s->error;
}

static bool build_record(struct byte_stream *s,
                         const struct ccoins_case *tc,
                         const uint8_t *nsizes)
{
    bool vout0 = false;
    bool vout1 = false;
    for (size_t i = 0; i < tc->out_count; i++) {
        vout0 = vout0 || tc->outs[i].vout == 0;
        vout1 = vout1 || tc->outs[i].vout == 1;
    }

    uint64_t ncode =
        8u * (uint64_t)(tc->nonzero_masks - ((vout0 || vout1) ? 0u : 1u)) +
        (tc->coinbase ? 1u : 0u) + (vout0 ? 2u : 0u) + (vout1 ? 4u : 0u);

    bool ok = true;
    ok &= stream_write_varint(s, (uint64_t)tc->version);
    ok &= stream_write_varint(s, ncode);
    for (size_t i = 0; i < tc->mask_count; i++)
        ok &= stream_write_u8(s, tc->masks[i]);
    for (size_t i = 0; i < tc->out_count; i++)
        ok &= append_expected_txout(s, &tc->outs[i], nsizes[i]);
    ok &= stream_write_varint(s, (uint64_t)tc->height);
    return ok && !s->error;
}

static bool seed_leveldb_record(const char *dir, const struct uint256 *txid,
                                const struct byte_stream *record)
{
    struct db_wrapper db;
    memset(&db, 0, sizeof(db));
    if (!db_wrapper_open(&db, dir, 1u << 20, false, true))
        return false;

    char key[33];
    key[0] = 'c';
    memcpy(key + 1, txid->data, 32);
    bool ok = db_write(&db, key, sizeof(key),
                       (const char *)record->data, record->size, true);
    db_wrapper_close(&db);
    return ok;
}

static bool compare_script(const char *label, uint32_t vout,
                           const uint8_t *got, size_t got_len,
                           const struct expected_out *want)
{
    if (got_len != want->script_len) {
        printf("    %s vout=%u script_len got=%zu want=%u\n",
               label, vout, got_len, want->script_len);
        return false;
    }
    if (memcmp(got, want->script, want->script_len) != 0) {
        printf("    %s vout=%u script bytes differ\n", label, vout);
        return false;
    }
    return true;
}

static bool compare_utxo_import(const struct ccoins_case *tc,
                                const struct byte_stream *record,
                                const struct uint256 *txid)
{
    struct utxo_import_row rows[16];
    memset(rows, 0, sizeof(rows));
    struct utxo_import_raw_entry raw;
    memset(&raw, 0, sizeof(raw));
    memcpy(raw.txid, txid->data, sizeof(raw.txid));
    raw.value = record->data;
    raw.value_len = (uint32_t)record->size;

    int n = utxo_import_decode_entry(&raw, rows, 16);
    bool ok = n == (int)tc->out_count;
    if (!ok)
        printf("    utxo_import rows got=%d want=%zu\n", n, tc->out_count);

    for (size_t i = 0; ok && i < tc->out_count; i++) {
        const struct expected_out *want = &tc->outs[i];
        ok = rows[i].vout == want->vout &&
             rows[i].value == want->value &&
             rows[i].height == tc->height &&
             rows[i].is_coinbase == (uint8_t)tc->coinbase &&
             !rows[i].script_overflow &&
             compare_script("utxo_import", rows[i].vout, rows[i].script,
                            rows[i].script_len, want);
        if (!ok) {
            printf("    utxo_import mismatch case=%s index=%zu\n",
                   tc->name, i);
        }
    }
    return ok;
}

static bool compare_coins_db(const char *dir, const struct ccoins_case *tc,
                             const struct uint256 *txid)
{
    struct coins_view_db cvdb;
    memset(&cvdb, 0, sizeof(cvdb));
    if (!coins_view_db_open(&cvdb, dir, 1u << 20, false, false))
        return false;

    struct coins c;
    coins_init(&c);
    bool ok = coins_view_db_get_coins(&cvdb, txid, &c);
    ok = ok && c.version == tc->version &&
         c.height == tc->height &&
         c.is_coinbase == tc->coinbase;

    for (size_t i = 0; ok && i < tc->out_count; i++) {
        const struct expected_out *want = &tc->outs[i];
        ok = want->vout < c.num_vout &&
             coins_is_available(&c, want->vout) &&
             c.vout[want->vout].value == want->value &&
             compare_script("coins_db", want->vout,
                            c.vout[want->vout].script_pub_key.data,
                            c.vout[want->vout].script_pub_key.size,
                            want);
    }
    if (!ok)
        printf("    coins_db mismatch case=%s num_vout=%zu\n",
               tc->name, c.num_vout);

    coins_free(&c);
    coins_view_db_close(&cvdb);
    return ok;
}

static bool capture_legacy_cb(const struct uint256 *txid,
                              const struct legacy_coins *coins,
                              void *ctx)
{
    struct legacy_capture *cap = ctx;
    struct uint256 want_txid;
    fill_txid(&want_txid, 0x30);
    cap->txid_ok = uint256_cmp(txid, &want_txid) == 0;
    cap->height = coins->height;
    cap->version = coins->version;
    cap->coinbase = coins->coinbase;
    cap->out_count = coins->num_vouts;
    if (cap->out_count > 16)
        cap->out_count = 16;
    for (size_t i = 0; i < cap->out_count; i++) {
        cap->outs[i].vout = coins->vouts[i].n;
        cap->outs[i].value = coins->vouts[i].value;
        cap->outs[i].script_len = (uint16_t)coins->vouts[i].script_len;
        if (cap->outs[i].script_len <= sizeof(cap->outs[i].script))
            memcpy(cap->outs[i].script, coins->vouts[i].script,
                   cap->outs[i].script_len);
    }
    return true;
}

static bool compare_chainstate_legacy(const char *dir,
                                      const struct ccoins_case *tc)
{
    void *h = NULL;
    if (!chainstate_legacy_open(dir, &h) || !h)
        return false;

    struct legacy_capture cap;
    memset(&cap, 0, sizeof(cap));
    int64_t n = chainstate_legacy_iter(h, capture_legacy_cb, &cap);
    bool ok = n == 1 &&
              cap.txid_ok &&
              cap.version == tc->version &&
              cap.height == tc->height &&
              cap.coinbase == tc->coinbase &&
              cap.out_count == tc->out_count;
    for (size_t i = 0; ok && i < tc->out_count; i++) {
        ok = cap.outs[i].vout == tc->outs[i].vout &&
             cap.outs[i].value == tc->outs[i].value &&
             compare_script("chainstate_legacy", cap.outs[i].vout,
                            cap.outs[i].script, cap.outs[i].script_len,
                            &tc->outs[i]);
    }
    if (!ok)
        printf("    chainstate_legacy mismatch case=%s n=%lld out_count=%zu\n",
               tc->name, (long long)n, cap.out_count);

    chainstate_legacy_close(h);
    return ok;
}

static bool run_case(const struct ccoins_case *tc, const uint8_t *nsizes)
{
    struct uint256 txid;
    fill_txid(&txid, tc->txid_seed);

    struct byte_stream record;
    stream_init(&record, 256);
    bool ok = build_record(&record, tc, nsizes);

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ccoins_decoder_kat", tc->name);
    ok = ok && seed_leveldb_record(dir, &txid, &record);
    ok = ok && compare_utxo_import(tc, &record, &txid);
    ok = ok && compare_coins_db(dir, tc, &txid);
    ok = ok && compare_chainstate_legacy(dir, tc);

    stream_free(&record);
    test_rm_rf_recursive(dir);
    return ok;
}

int test_ccoins_decoder_kat(void)
{
    int failures = 0;

    printf("ccoins_decoder_kat: vout0-only coinbase... ");
    {
        struct expected_out out[1];
        bool ok = expected_from_special(&out[0], 0, 5000000000LL, 0, 0x40);
        static const uint8_t no_masks[] = {0};
        static const uint8_t nsizes[] = {0};
        struct ccoins_case tc = {
            .name = "vout0",
            .coinbase = true,
            .version = 1,
            .height = 42,
            .txid_seed = 0x30,
            .masks = no_masks,
            .mask_count = 0,
            .nonzero_masks = 0,
            .outs = out,
            .out_count = 1,
        };
        ok = ok && run_case(&tc, nsizes);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("ccoins_decoder_kat: multi-mask special/raw scripts... ");
    {
        struct expected_out out[7];
        bool ok = true;
        ok &= expected_from_special(&out[0], 2, 1, 0, 0x51);
        ok &= expected_from_special(&out[1], 3, 2, 1, 0x61);
        ok &= expected_from_special(&out[2], 4, 3, 2, 0x00);
        ok &= expected_from_special(&out[3], 5, 4, 3, 0x00);
        ok &= expected_from_special(&out[4], 10, 5, 4, 0x00);
        ok &= expected_from_special(&out[5], 17, 6, 5, 0x00);
        ok &= expected_from_raw(&out[6], 18, 7);
        static const uint8_t masks[] = {0x0f, 0x81, 0x01};
        static const uint8_t nsizes[] = {0, 1, 2, 3, 4, 5, 12};
        struct ccoins_case tc = {
            .name = "multi",
            .coinbase = false,
            .version = 2,
            .height = 3141592,
            .txid_seed = 0x30,
            .masks = masks,
            .mask_count = sizeof(masks),
            .nonzero_masks = 3,
            .outs = out,
            .out_count = 7,
        };
        ok = ok && run_case(&tc, nsizes);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
