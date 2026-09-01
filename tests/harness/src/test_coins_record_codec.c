/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "../../storage/src/coins_record_codec.h"

#include "coins/compressor.h"
#include "core/serialize.h"
#include "services/utxo_import_pipeline.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct test_decode_ctx {
    struct coins *coins;
};

static void fill_hash(uint8_t *out, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++)
        out[i] = (uint8_t)(seed + i);
}

static void set_p2pkh(struct tx_out *out, int64_t value, uint8_t seed)
{
    uint8_t h[20];
    fill_hash(h, sizeof(h), seed);
    out->value = value;
    out->script_pub_key.size = 25;
    out->script_pub_key.data[0] = 0x76;
    out->script_pub_key.data[1] = 0xa9;
    out->script_pub_key.data[2] = 0x14;
    memcpy(out->script_pub_key.data + 3, h, sizeof(h));
    out->script_pub_key.data[23] = 0x88;
    out->script_pub_key.data[24] = 0xac;
}

static void set_p2sh(struct tx_out *out, int64_t value, uint8_t seed)
{
    uint8_t h[20];
    fill_hash(h, sizeof(h), seed);
    out->value = value;
    out->script_pub_key.size = 23;
    out->script_pub_key.data[0] = 0xa9;
    out->script_pub_key.data[1] = 0x14;
    memcpy(out->script_pub_key.data + 2, h, sizeof(h));
    out->script_pub_key.data[22] = 0x87;
}

static void set_raw_script(struct tx_out *out, int64_t value, uint8_t seed)
{
    out->value = value;
    out->script_pub_key.size = 9;
    out->script_pub_key.data[0] = 0x51;
    out->script_pub_key.data[1] = 0x21;
    fill_hash(out->script_pub_key.data + 2, 7, seed);
}

static bool decode_to_coins_begin(const struct coins_record_header *hdr,
                                  void *ctx)
{
    struct test_decode_ctx *c = (struct test_decode_ctx *)ctx;
    if (!hdr || !c || !c->coins)
        return false;
    c->coins->version = hdr->version;
    c->coins->is_coinbase = hdr->is_coinbase;
    return coins_alloc(c->coins, hdr->num_avail);
}

static bool decode_to_coins_output(const struct coins_record_output *out,
                                   void *ctx)
{
    struct test_decode_ctx *c = (struct test_decode_ctx *)ctx;
    if (!out || !c || !c->coins || out->vout >= c->coins->num_vout)
        return false;
    c->coins->vout[out->vout].value = out->value;
    script_set(&c->coins->vout[out->vout].script_pub_key,
               out->script, out->script_len);
    return true;
}

static bool decode_record_to_coins(const struct byte_stream *record,
                                   struct coins *out,
                                   struct coins_record_decode_result *res_out)
{
    coins_init(out);
    struct test_decode_ctx ctx = { .coins = out };
    struct coins_record_decode_options opts = {
        .mode = COINS_RECORD_DECODE_COINS_DB,
        .max_outputs = 0,
        .scratch = NULL,
    };
    struct coins_record_decode_ops ops = {
        .begin = decode_to_coins_begin,
        .output = decode_to_coins_output,
    };
    struct coins_record_decode_result res;
    enum coins_record_decode_status st =
        coins_record_decode(record->data, record->size, &opts, &ops, &ctx,
                            &res);
    if (st != COINS_RECORD_DECODE_OK)
        return false;
    out->height = res.height;
    coins_cleanup(out);
    if (res_out)
        *res_out = res;
    return true;
}

static bool encode_coins(const struct coins *coins, struct byte_stream *record)
{
    stream_init(record, 256);
    return coins_record_encode(coins, record);
}

static bool roundtrip_byte_identical(const struct coins *src)
{
    struct byte_stream a;
    if (!encode_coins(src, &a))
        return false;

    struct coins decoded;
    bool ok = decode_record_to_coins(&a, &decoded, NULL);

    struct byte_stream b;
    memset(&b, 0, sizeof(b));
    if (ok)
        ok = encode_coins(&decoded, &b);
    ok = ok && a.size == b.size && memcmp(a.data, b.data, a.size) == 0;

    stream_free(&b);
    coins_free(&decoded);
    stream_free(&a);
    return ok;
}

static bool build_boundary_vout_record(struct byte_stream *s,
                                       uint32_t vout,
                                       uint8_t mask_bit,
                                       uint32_t height)
{
    stream_init(s, 2048);
    bool ok = true;
    ok &= stream_write_varint(s, 1);
    ok &= stream_write_varint(s, 0);
    for (int i = 0; i < 511; i++)
        ok &= stream_write_u8(s, 0);
    ok &= stream_write_u8(s, (uint8_t)(1u << mask_bit));

    uint8_t hash[20];
    fill_hash(hash, sizeof(hash), 0x90);
    ok &= stream_write_varint(s, compress_amount(777));
    ok &= stream_write_varint(s, 0);
    ok &= stream_write_bytes(s, hash, sizeof(hash));
    ok &= stream_write_varint(s, height);
    (void)vout;
    return ok && !s->error;
}

static bool build_utxo_short_height_record(struct byte_stream *s)
{
    stream_init(s, 64);
    uint8_t hash[20];
    fill_hash(hash, sizeof(hash), 0x40);
    bool ok = true;
    ok &= stream_write_varint(s, 1);
    ok &= stream_write_varint(s, 3); /* coinbase + vout0 */
    ok &= stream_write_varint(s, compress_amount(1234));
    ok &= stream_write_varint(s, 0);
    ok &= stream_write_bytes(s, hash, sizeof(hash));
    return ok && !s->error;
}

static bool build_utxo_raw_script_record(struct byte_stream *s,
                                         size_t raw_len,
                                         uint32_t height)
{
    stream_init(s, raw_len + 32);
    bool ok = true;
    ok &= stream_write_varint(s, 1);
    ok &= stream_write_varint(s, 2); /* vout0 */
    ok &= stream_write_varint(s, compress_amount(99));
    ok &= stream_write_varint(s, (uint64_t)raw_len + 6u);
    for (size_t i = 0; i < raw_len; i++) {
        uint8_t ch = (i == 0) ? 0x6a : (uint8_t)(0x20 + (i % 71));
        ok &= stream_write_u8(s, ch);
    }
    ok &= stream_write_varint(s, height);
    return ok && !s->error;
}

static bool test_roundtrip_cases(void)
{
    struct coins coinbase;
    coins_init(&coinbase);
    if (!coins_alloc(&coinbase, 1))
        return false;
    coinbase.is_coinbase = true;
    coinbase.version = 1;
    coinbase.height = 42;
    set_p2pkh(&coinbase.vout[0], 5000000000LL, 0x10);
    bool ok = roundtrip_byte_identical(&coinbase);
    coins_free(&coinbase);
    if (!ok)
        return false;

    struct coins multi;
    coins_init(&multi);
    if (!coins_alloc(&multi, 11))
        return false;
    multi.is_coinbase = false;
    multi.version = 2;
    multi.height = 3141592;
    set_p2pkh(&multi.vout[0], 1, 0x20);
    set_p2sh(&multi.vout[1], 100000000, 0x30);
    set_raw_script(&multi.vout[10], 123456789, 0x40);
    ok = roundtrip_byte_identical(&multi);
    coins_free(&multi);
    if (!ok)
        return false;

    struct coins cap;
    coins_init(&cap);
    if (!coins_alloc(&cap, 4096))
        return false;
    cap.is_coinbase = false;
    cap.version = 3;
    cap.height = 700000;
    set_p2pkh(&cap.vout[4095], 987654321, 0x50);
    ok = roundtrip_byte_identical(&cap);
    coins_free(&cap);
    return ok;
}

static bool test_vout_cap_preserved(void)
{
    struct byte_stream record;
    bool ok = build_boundary_vout_record(&record, 4096, 6, 2222);

    struct coins decoded;
    struct coins_record_decode_result res;
    ok = ok && decode_record_to_coins(&record, &decoded, &res);
    ok = ok && res.num_avail == 4096;
    ok = ok && decoded.num_vout == 0;
    ok = ok && decoded.height == (int)compress_amount(777);

    coins_free(&decoded);
    stream_free(&record);
    return ok;
}

static bool test_utxo_import_boundaries(void)
{
    bool ok = true;

    struct byte_stream short_height;
    ok = ok && build_utxo_short_height_record(&short_height);
    struct utxo_import_raw_entry raw;
    memset(&raw, 0, sizeof(raw));
    memset(raw.txid, 0x22, sizeof(raw.txid));
    raw.value = short_height.data;
    raw.value_len = (uint32_t)short_height.size;
    struct utxo_import_row row;
    memset(&row, 0, sizeof(row));
    int n = utxo_import_decode_entry(&raw, &row, 1);
    ok = ok && n == 1 && row.height == 0 && row.value == 1234 &&
         row.script_type == 1 && row.has_address == 1;
    free(row.script_overflow);
    stream_free(&short_height);

    struct byte_stream raw_script;
    ok = ok && build_utxo_raw_script_record(&raw_script, 10240, 88);
    memset(&raw, 0, sizeof(raw));
    memset(raw.txid, 0x33, sizeof(raw.txid));
    raw.value = raw_script.data;
    raw.value_len = (uint32_t)raw_script.size;
    memset(&row, 0, sizeof(row));
    n = utxo_import_decode_entry(&raw, &row, 1);
    ok = ok && n == 1 && row.height == 88 && row.script_len == 10240 &&
         row.script_overflow != NULL && row.script_type == 3;
    free(row.script_overflow);
    stream_free(&raw_script);

    uint32_t out_len = 0;
    struct zcl_result len_65535 =
        utxo_import_value_len_checked(65535u, &out_len);
    ok = ok && len_65535.ok && out_len == 65535u;
    struct zcl_result len_65536 =
        utxo_import_value_len_checked(65536u, &out_len);
    ok = ok && len_65536.ok && out_len == 65536u;

    return ok;
}

int test_coins_record_codec(void)
{
    int failures = 0;

    printf("coins_record_codec: canonical decode/encode byte identity... ");
    if (test_roundtrip_cases()) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    printf("coins_record_codec: coins_db 4096-vout cap preserved... ");
    if (test_vout_cap_preserved()) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    printf("coins_record_codec: utxo import boundary behavior preserved... ");
    if (test_utxo_import_boundaries()) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    return failures;
}

int test_storage_coins_utxo(void)
{
    int failures = 0;
    failures += test_coins();
    failures += test_chainstate_legacy_reader();
    failures += test_utxo_import_pipeline();
    failures += test_ccoins_decoder_kat();
    failures += test_coins_record_codec();
    return failures;
}
