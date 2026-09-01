/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "coins/compressor.h"
#include "core/serialize.h"
#include "services/utxo_import_pipeline.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool build_large_ccoins_record(struct byte_stream *s, int outputs,
                                      uint32_t height)
{
    if (!s || outputs < 2 || ((outputs - 2) % 8) != 0)
        return false;

    int mask_bytes = (outputs - 2) / 8;
    uint64_t ncode = ((uint64_t)mask_bytes * 8u) | 0x07u;
    unsigned char hash[20];
    memset(hash, 0x51, sizeof(hash));

    bool ok = true;
    ok &= stream_write_varint(s, 1);      /* nVersion */
    ok &= stream_write_varint(s, ncode);  /* coinbase + vout0 + vout1 */
    for (int i = 0; i < mask_bytes; i++)
        ok &= stream_write_u8(s, 0xff);
    for (int i = 0; i < outputs; i++) {
        hash[0] = (unsigned char)(0x20 + (i % 64));
        ok &= stream_write_varint(s, compress_amount(1));
        ok &= stream_write_varint(s, 0); /* compressed P2PKH */
        ok &= stream_write_bytes(s, hash, sizeof(hash));
    }
    ok &= stream_write_varint(s, height);
    return ok && !s->error;
}

int test_utxo_import_pipeline(void)
{
    int failures = 0;

    printf("utxo_import_pipeline: CCoins >65535 bytes decodes fully... ");
    {
        const int outputs = 3002;
        const uint32_t height = 3141592;
        struct byte_stream s;
        stream_init(&s, 70000);
        bool ok = build_large_ccoins_record(&s, outputs, height);

        struct utxo_import_row *rows =
            zcl_malloc(sizeof(*rows) * (size_t)outputs,
                       "test_utxo_import_rows");
        ok = ok && rows != NULL;
        if (rows)
            memset(rows, 0, sizeof(*rows) * (size_t)outputs);

        struct utxo_import_raw_entry raw;
        memset(&raw, 0, sizeof(raw));
        memset(raw.txid, 0x42, sizeof(raw.txid));
        raw.value = s.data;
        raw.value_len = (uint32_t)s.size;
        size_t record_len = s.size;

        int n = rows ? utxo_import_decode_entry(&raw, rows, outputs) : 0;
        ok = ok && record_len > 65535;
        ok = ok && n == outputs;
        if (rows && n == outputs) {
            ok = ok && rows[0].vout == 0;
            ok = ok && rows[0].height == (int32_t)height;
            ok = ok && rows[0].value == 1;
            ok = ok && rows[0].script_len == 25;
            ok = ok && rows[0].script_type == 1;
            ok = ok && rows[0].has_address == 1;
            ok = ok && rows[outputs - 1].vout == (uint32_t)(outputs - 1);
            ok = ok && rows[outputs - 1].height == (int32_t)height;
            ok = ok && rows[outputs - 1].value == 1;
        }

        free(rows);
        stream_free(&s);
        if (ok) printf("OK\n");
        else { printf("FAIL (len=%zu rows=%d)\n", record_len, n); failures++; }
    }

    printf("utxo_import_pipeline: oversized CCoins value refuses import... ");
    {
        uint32_t out_len = 0;
        struct zcl_result exact =
            utxo_import_value_len_checked(UTXO_IMPORT_VALUE_MAX_BYTES,
                                          &out_len);
        struct zcl_result too_large =
            utxo_import_value_len_checked(
                (size_t)UTXO_IMPORT_VALUE_MAX_BYTES + 1u, &out_len);
        struct zcl_result null_out =
            utxo_import_value_len_checked(16, NULL);
        bool ok = exact.ok &&
                  out_len == UTXO_IMPORT_VALUE_MAX_BYTES &&
                  !too_large.ok &&
                  !null_out.ok;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
