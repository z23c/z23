/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "coins_record_codec.h"

#include "coins/compressor.h"
#include "script/script.h"
#include "util/safe_alloc.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define COINS_RECORD_MASK_CODE_LIMIT 10000u
#define COINS_RECORD_BOUNDED_AVAIL 4096u
#define COINS_RECORD_UTXO_IMPORT_RAW_SCRIPT_CAP 10240u
#define COINS_RECORD_SPECIAL_SCRIPTS 6u

static const struct coins_record_status_name_row {
    enum coins_record_decode_status code;
    const char *value;
} coins_record_status_names[] = {
    { COINS_RECORD_DECODE_OK, "ok" },
    { COINS_RECORD_DECODE_NULL_ARG, "null_arg" },
    { COINS_RECORD_DECODE_VERSION_TRUNCATED, "version_truncated" },
    { COINS_RECORD_DECODE_CODE_TRUNCATED, "code_truncated" },
    { COINS_RECORD_DECODE_MASK_CODE_LIMIT, "mask_code_limit" },
    { COINS_RECORD_DECODE_MASK_TRUNCATED, "mask_truncated" },
    { COINS_RECORD_DECODE_OOM, "oom" },
    { COINS_RECORD_DECODE_BEGIN_FAILED, "begin_failed" },
    { COINS_RECORD_DECODE_AMOUNT_TRUNCATED, "amount_truncated" },
    { COINS_RECORD_DECODE_SCRIPT_SIZE_TRUNCATED, "script_size_truncated" },
    { COINS_RECORD_DECODE_BAD_SPECIAL_SCRIPT_SIZE, "bad_special_script_size" },
    { COINS_RECORD_DECODE_SPECIAL_SCRIPT_TRUNCATED, "special_script_truncated" },
    { COINS_RECORD_DECODE_SCRIPT_DECOMPRESS_FAILED, "script_decompress_failed" },
    { COINS_RECORD_DECODE_RAW_SCRIPT_TOO_LARGE, "raw_script_too_large" },
    { COINS_RECORD_DECODE_RAW_SCRIPT_TRUNCATED, "raw_script_truncated" },
    { COINS_RECORD_DECODE_OUTPUT_FAILED, "output_failed" },
    { COINS_RECORD_DECODE_HEIGHT_TRUNCATED, "height_truncated" },
};

const char *coins_record_decode_status_name(enum coins_record_decode_status st)
{
    const size_t rows = sizeof(coins_record_status_names) /
                        sizeof(coins_record_status_names[0]);
    for (size_t i = 0; i < rows; i++)
        if (coins_record_status_names[i].code == st)
            return coins_record_status_names[i].value;
    return "unknown";
}

void coins_record_scratch_free(struct coins_record_scratch *scratch)
{
    if (!scratch)
        return;
    free(scratch->avail);
    scratch->avail = NULL;
    scratch->avail_cap = 0;
}

static bool mode_is_bounded(enum coins_record_decode_mode mode)
{
    return mode == COINS_RECORD_DECODE_COINS_DB ||
           mode == COINS_RECORD_DECODE_UTXO_IMPORT;
}

static enum coins_record_decode_status ensure_dynamic_avail(
    struct coins_record_scratch *scratch,
    size_t need)
{
    if (!scratch)
        return COINS_RECORD_DECODE_NULL_ARG;
    if (need <= scratch->avail_cap)
        return COINS_RECORD_DECODE_OK;

    size_t cap = scratch->avail_cap ? scratch->avail_cap : 16;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) {
            cap = need;
            break;
        }
        cap *= 2;
    }

    bool *p = zcl_realloc(scratch->avail, cap * sizeof(*p),
                          "coins_record_avail");
    if (!p)
        return COINS_RECORD_DECODE_OOM;
    scratch->avail = p;
    scratch->avail_cap = cap;
    return COINS_RECORD_DECODE_OK;
}

static enum coins_record_decode_status append_avail(
    bool *bounded,
    struct coins_record_scratch *scratch,
    bool dynamic,
    size_t *len,
    bool present)
{
    if (dynamic) {
        enum coins_record_decode_status st =
            ensure_dynamic_avail(scratch, *len + 1);
        if (st != COINS_RECORD_DECODE_OK)
            return st;
        scratch->avail[*len] = present;
        (*len)++;
        return COINS_RECORD_DECODE_OK;
    }

    /* coins_db and utxo_import_pipeline cap the availability vector at 4096
     * vouts.  When a record advertises a live output beyond this bound, the
     * decoders still consume all mask bytes but do not skip the extra txout
     * payload before reading height.  Tightening that into reject-or-skip
     * requires full-history replay. */
    if (*len < COINS_RECORD_BOUNDED_AVAIL) {
        bounded[*len] = present;
        (*len)++;
    }
    return COINS_RECORD_DECODE_OK;
}

static const bool *avail_data(const bool *bounded,
                              const struct coins_record_scratch *scratch,
                              bool dynamic)
{
    return dynamic ? scratch->avail : bounded;
}

static enum coins_record_decode_status read_raw_or_special_script(
    struct byte_stream *s,
    enum coins_record_decode_mode mode,
    uint64_t nsize,
    const uint8_t **script_out,
    size_t *script_len_out,
    struct script *sc,
    uint8_t import_raw[COINS_RECORD_UTXO_IMPORT_RAW_SCRIPT_CAP])
{
    script_init(sc);

    if (nsize < COINS_RECORD_SPECIAL_SCRIPTS) {
        unsigned int special =
            script_compress_special_size((unsigned int)nsize);
        uint8_t buf[65];
        if (special == 0 || special > sizeof(buf))
            return COINS_RECORD_DECODE_BAD_SPECIAL_SCRIPT_SIZE;
        if (!stream_read_bytes(s, buf, special))
            return COINS_RECORD_DECODE_SPECIAL_SCRIPT_TRUNCATED;
        if (!script_decompress(sc, (unsigned int)nsize, buf, special))
            return COINS_RECORD_DECODE_SCRIPT_DECOMPRESS_FAILED;
        *script_out = sc->data;
        *script_len_out = sc->size;
        return COINS_RECORD_DECODE_OK;
    }

    uint64_t raw_len_u = nsize - COINS_RECORD_SPECIAL_SCRIPTS;
    if (mode == COINS_RECORD_DECODE_UTXO_IMPORT) {
        /* Preserves the importer truncation exactly.  It reads at most 10240 script bytes and leaves any
         * remainder in the stream, so the later height varint may be read from
         * script bytes.  Do not "fix" without replaying real chainstate. */
        size_t read_len = raw_len_u > COINS_RECORD_UTXO_IMPORT_RAW_SCRIPT_CAP
                            ? COINS_RECORD_UTXO_IMPORT_RAW_SCRIPT_CAP
                            : (size_t)raw_len_u;
        if (!stream_read_bytes(s, import_raw, read_len))
            return COINS_RECORD_DECODE_RAW_SCRIPT_TRUNCATED;
        *script_out = import_raw;
        *script_len_out = read_len;
        return COINS_RECORD_DECODE_OK;
    }

    if (raw_len_u > MAX_SCRIPT_SIZE) {
        if (mode == COINS_RECORD_DECODE_CHAINSTATE_LEGACY) {
            if (raw_len_u > s->size - s->read_pos)
                return COINS_RECORD_DECODE_RAW_SCRIPT_TRUNCATED;
            sc->data[0] = OP_RETURN;
            sc->size = 1;
            s->read_pos += (size_t)raw_len_u;
            *script_out = sc->data;
            *script_len_out = sc->size;
            return COINS_RECORD_DECODE_OK;
        }
        return COINS_RECORD_DECODE_RAW_SCRIPT_TOO_LARGE;
    }

    size_t raw_len = (size_t)raw_len_u;
    if (!stream_read_bytes(s, sc->data, raw_len))
        return COINS_RECORD_DECODE_RAW_SCRIPT_TRUNCATED;
    sc->size = raw_len;
    *script_out = sc->data;
    *script_len_out = sc->size;
    return COINS_RECORD_DECODE_OK;
}

static enum coins_record_decode_status decode_one_output(
    struct byte_stream *s,
    const struct coins_record_decode_result *partial,
    enum coins_record_decode_mode mode,
    size_t vout,
    const struct coins_record_decode_ops *ops,
    void *ctx)
{
    uint64_t compressed_amount = 0;
    if (!stream_read_varint(s, &compressed_amount))
        return COINS_RECORD_DECODE_AMOUNT_TRUNCATED;

    uint64_t nsize = 0;
    if (!stream_read_varint(s, &nsize))
        return COINS_RECORD_DECODE_SCRIPT_SIZE_TRUNCATED;

    struct script sc;
    uint8_t import_raw[COINS_RECORD_UTXO_IMPORT_RAW_SCRIPT_CAP];
    const uint8_t *script = NULL;
    size_t script_len = 0;
    enum coins_record_decode_status st = read_raw_or_special_script(
        s, mode, nsize, &script, &script_len, &sc, import_raw);
    if (st != COINS_RECORD_DECODE_OK)
        return st;

    if (ops && ops->output) {
        struct coins_record_output out = {
            .vout = (uint32_t)vout,
            .value = (int64_t)decompress_amount(compressed_amount),
            .nsize = nsize,
            .script = script,
            .script_len = script_len,
            .version = partial->version,
            .is_coinbase = partial->is_coinbase,
        };
        if (!ops->output(&out, ctx))
            return COINS_RECORD_DECODE_OUTPUT_FAILED;
    }

    return COINS_RECORD_DECODE_OK;
}

static bool coins_record_decode_args_ok(
    const uint8_t *value,
    const struct coins_record_decode_options *opts,
    const struct coins_record_decode_result *result)
{
    return value && opts && result;
}

static enum coins_record_decode_status coins_record_read_header(
    struct byte_stream *s,
    const struct coins_record_decode_options *opts,
    struct coins_record_decode_result *result,
    bool *avail0,
    bool *avail1)
{
    uint64_t version_u = 0;
    if (!stream_read_varint(s, &version_u))
        return COINS_RECORD_DECODE_VERSION_TRUNCATED;
    result->version = (int)version_u;

    uint64_t code = 0;
    if (!stream_read_varint(s, &code))
        return COINS_RECORD_DECODE_CODE_TRUNCATED;

    *avail0 = (code & 2u) != 0u;
    *avail1 = (code & 4u) != 0u;
    unsigned int nmask_code =
        (unsigned int)(code / 8u) + ((*avail0 || *avail1) ? 0u : 1u);
    result->is_coinbase = (code & 1u) != 0u;
    result->nmask_code = nmask_code;

    if (mode_is_bounded(opts->mode) &&
        nmask_code > COINS_RECORD_MASK_CODE_LIMIT)
        return COINS_RECORD_DECODE_MASK_CODE_LIMIT;
    return COINS_RECORD_DECODE_OK;
}

static enum coins_record_decode_status coins_record_read_avail_mask(
    struct byte_stream *s,
    enum coins_record_decode_mode mode,
    bool *bounded,
    struct coins_record_scratch *scratch,
    bool dynamic,
    unsigned int nmask_code,
    size_t *num_avail)
{
    unsigned int mask_remaining = nmask_code;
    while (mask_remaining > 0) {
        uint8_t ch = 0;
        if (!stream_read_u8(s, &ch)) {
            if (mode == COINS_RECORD_DECODE_UTXO_IMPORT)
                break;
            return COINS_RECORD_DECODE_MASK_TRUNCATED;
        }
        for (unsigned int p = 0; p < 8; p++) {
            enum coins_record_decode_status st = append_avail(
                bounded, scratch, dynamic, num_avail,
                (ch & (1u << p)) != 0u);
            if (st != COINS_RECORD_DECODE_OK)
                return st;
        }
        if (ch != 0)
            mask_remaining--;
    }
    return COINS_RECORD_DECODE_OK;
}

static size_t coins_record_count_live(const bool *avail, size_t num_avail)
{
    size_t live = 0;
    for (size_t i = 0; i < num_avail; i++)
        if (avail[i])
            live++;
    return live;
}

static enum coins_record_decode_status coins_record_emit_begin(
    const struct coins_record_decode_ops *ops,
    void *ctx,
    const struct coins_record_decode_result *result)
{
    if (ops && ops->begin) {
        struct coins_record_header hdr = {
            .version = result->version,
            .is_coinbase = result->is_coinbase,
            .nmask_code = result->nmask_code,
            .num_avail = result->num_avail,
            .live_outputs = result->live_outputs,
        };
        if (!ops->begin(&hdr, ctx))
            return COINS_RECORD_DECODE_BEGIN_FAILED;
    }
    return COINS_RECORD_DECODE_OK;
}

static enum coins_record_decode_status coins_record_decode_outputs(
    struct byte_stream *s,
    const struct coins_record_decode_options *opts,
    const struct coins_record_decode_ops *ops,
    void *ctx,
    const bool *avail,
    size_t num_avail,
    struct coins_record_decode_result *result)
{
    size_t max_outputs = opts->max_outputs ? opts->max_outputs : SIZE_MAX;
    for (size_t i = 0; i < num_avail; i++) {
        if (!avail[i])
            continue;
        if (result->outputs_emitted >= max_outputs)
            break;

        enum coins_record_decode_status st =
            decode_one_output(s, result, opts->mode, i, ops, ctx);
        if (st != COINS_RECORD_DECODE_OK) {
            if (opts->mode == COINS_RECORD_DECODE_UTXO_IMPORT)
                break;
            return st;
        }
        result->outputs_emitted++;
    }
    return COINS_RECORD_DECODE_OK;
}

static enum coins_record_decode_status coins_record_read_height(
    struct byte_stream *s,
    enum coins_record_decode_mode mode,
    struct coins_record_decode_result *result)
{
    uint64_t height_u = 0;
    if (stream_read_varint(s, &height_u)) {
        result->height = (int)height_u;
        result->height_found = true;
        result->height_in_legacy_import_range = height_u <= 10000000u;
    } else if (mode != COINS_RECORD_DECODE_UTXO_IMPORT) {
        return COINS_RECORD_DECODE_HEIGHT_TRUNCATED;
    }
    return COINS_RECORD_DECODE_OK;
}

enum coins_record_decode_status coins_record_decode(
    const uint8_t *value,
    size_t value_len,
    const struct coins_record_decode_options *opts,
    const struct coins_record_decode_ops *ops,
    void *ctx,
    struct coins_record_decode_result *result)
{
    if (!coins_record_decode_args_ok(value, opts, result))
        return COINS_RECORD_DECODE_NULL_ARG;

    memset(result, 0, sizeof(*result));

    bool bounded_avail[COINS_RECORD_BOUNDED_AVAIL];
    memset(bounded_avail, 0, sizeof(bounded_avail));
    bool dynamic = !mode_is_bounded(opts->mode);
    if (dynamic && !opts->scratch)
        return COINS_RECORD_DECODE_NULL_ARG;

    struct byte_stream s;
    stream_init_from_data(&s, value, value_len);

    bool avail0 = false;
    bool avail1 = false;
    enum coins_record_decode_status st = coins_record_read_header(
        &s, opts, result, &avail0, &avail1);
    if (st != COINS_RECORD_DECODE_OK)
        return st;

    size_t num_avail = 0;
    st = append_avail(bounded_avail, opts->scratch, dynamic, &num_avail,
                      avail0);
    if (st != COINS_RECORD_DECODE_OK)
        return st;
    st = append_avail(bounded_avail, opts->scratch, dynamic, &num_avail,
                      avail1);
    if (st != COINS_RECORD_DECODE_OK)
        return st;

    st = coins_record_read_avail_mask(&s, opts->mode, bounded_avail,
                                      opts->scratch, dynamic,
                                      result->nmask_code, &num_avail);
    if (st != COINS_RECORD_DECODE_OK)
        return st;

    const bool *avail = avail_data(bounded_avail, opts->scratch, dynamic);
    size_t live = coins_record_count_live(avail, num_avail);
    result->num_avail = num_avail;
    result->live_outputs = live;

    st = coins_record_emit_begin(ops, ctx, result);
    if (st != COINS_RECORD_DECODE_OK)
        return st;

    st = coins_record_decode_outputs(&s, opts, ops, ctx, avail, num_avail,
                                     result);
    if (st != COINS_RECORD_DECODE_OK)
        return st;

    st = coins_record_read_height(&s, opts->mode, result);
    if (st != COINS_RECORD_DECODE_OK)
        return st;

    return COINS_RECORD_DECODE_OK;
}

static bool coins_record_vout_is_live(const struct coins *cc, size_t vi)
{
    return vi < cc->num_vout && !tx_out_is_null(&cc->vout[vi]);
}

static unsigned int coins_record_mask_byte_count(const struct coins *cc)
{
    unsigned int nmask_size = 0;
    for (size_t vi = 2; vi < cc->num_vout; vi++) {
        if (!tx_out_is_null(&cc->vout[vi])) {
            unsigned int byte_pos = (unsigned int)((vi - 2) / 8) + 1u;
            if (byte_pos > nmask_size)
                nmask_size = byte_pos;
        }
    }
    return nmask_size;
}

static uint8_t coins_record_mask_byte(const struct coins *cc, unsigned int mi)
{
    uint8_t ch = 0;
    for (unsigned int p = 0; p < 8; p++) {
        size_t idx = 2u + (size_t)mi * 8u + p;
        if (coins_record_vout_is_live(cc, idx))
            ch |= (uint8_t)(1u << p);
    }
    return ch;
}

static unsigned int coins_record_count_nonzero_mask_bytes(
    const struct coins *cc,
    unsigned int nmask_size)
{
    unsigned int nmask_code = 0;
    for (unsigned int mi = 0; mi < nmask_size; mi++) {
        if (coins_record_mask_byte(cc, mi) != 0)
            nmask_code++;
    }
    return nmask_code;
}

static uint64_t coins_record_encode_code(const struct coins *cc,
                                         unsigned int nmask_code)
{
    bool vout0 = coins_record_vout_is_live(cc, 0);
    bool vout1 = coins_record_vout_is_live(cc, 1);
    return 8u * (uint64_t)(nmask_code - ((vout0 || vout1) ? 0u : 1u)) +
           (cc->is_coinbase ? 1u : 0u) +
           (vout0 ? 2u : 0u) +
           (vout1 ? 4u : 0u);
}

bool coins_record_encode(const struct coins *cc, struct byte_stream *s)
{
    if (!cc || !s)
        return false;

    bool ok = true;
    ok &= stream_write_varint(s, (uint64_t)cc->version);

    unsigned int nmask_size = coins_record_mask_byte_count(cc);
    unsigned int nmask_code =
        coins_record_count_nonzero_mask_bytes(cc, nmask_size);
    ok &= stream_write_varint(s, coins_record_encode_code(cc, nmask_code));

    for (unsigned int mi = 0; mi < nmask_size; mi++) {
        ok &= stream_write_u8(s, coins_record_mask_byte(cc, mi));
    }

    for (size_t vi = 0; vi < cc->num_vout; vi++) {
        if (tx_out_is_null(&cc->vout[vi]))
            continue;
        uint64_t compressed_val = compress_amount((uint64_t)cc->vout[vi].value);
        ok &= stream_write_varint(s, compressed_val);

        uint8_t compressed[MAX_SCRIPT_SIZE];
        size_t compressed_len = 0;
        if (script_compress(&cc->vout[vi].script_pub_key, compressed,
                            &compressed_len)) {
            ok &= stream_write_bytes(s, compressed, compressed_len);
        } else {
            uint64_t nsize =
                cc->vout[vi].script_pub_key.size +
                COINS_RECORD_SPECIAL_SCRIPTS;
            ok &= stream_write_varint(s, nsize);
            ok &= stream_write_bytes(s, cc->vout[vi].script_pub_key.data,
                                     cc->vout[vi].script_pub_key.size);
        }
    }

    ok &= stream_write_varint(s, (uint64_t)cc->height);
    return ok && !s->error;
}
