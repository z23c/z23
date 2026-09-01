/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_STORAGE_COINS_RECORD_CODEC_H
#define ZCL_STORAGE_COINS_RECORD_CODEC_H

#include "coins/coins.h"
#include "core/serialize.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bitcoin Core 0.8+ CCoins record codec.
 *
 * This is deliberately policy-parametric.  The three live callers historically
 * decoded the same byte format with different trust boundaries and truncation
 * behavior.  Those differences are consensus-adjacent import behavior, so the
 * shared parser preserves them through explicit modes instead of normalizing
 * them into one stricter predicate.
 */

enum coins_record_decode_mode {
    COINS_RECORD_DECODE_COINS_DB = 0,
    COINS_RECORD_DECODE_CHAINSTATE_LEGACY = 1,
    COINS_RECORD_DECODE_UTXO_IMPORT = 2,
};

enum coins_record_decode_status {
    COINS_RECORD_DECODE_OK = 0,
    COINS_RECORD_DECODE_NULL_ARG,
    COINS_RECORD_DECODE_VERSION_TRUNCATED,
    COINS_RECORD_DECODE_CODE_TRUNCATED,
    COINS_RECORD_DECODE_MASK_CODE_LIMIT,
    COINS_RECORD_DECODE_MASK_TRUNCATED,
    COINS_RECORD_DECODE_OOM,
    COINS_RECORD_DECODE_BEGIN_FAILED,
    COINS_RECORD_DECODE_AMOUNT_TRUNCATED,
    COINS_RECORD_DECODE_SCRIPT_SIZE_TRUNCATED,
    COINS_RECORD_DECODE_BAD_SPECIAL_SCRIPT_SIZE,
    COINS_RECORD_DECODE_SPECIAL_SCRIPT_TRUNCATED,
    COINS_RECORD_DECODE_SCRIPT_DECOMPRESS_FAILED,
    COINS_RECORD_DECODE_RAW_SCRIPT_TOO_LARGE,
    COINS_RECORD_DECODE_RAW_SCRIPT_TRUNCATED,
    COINS_RECORD_DECODE_OUTPUT_FAILED,
    COINS_RECORD_DECODE_HEIGHT_TRUNCATED,
};

struct coins_record_scratch {
    bool *avail;
    size_t avail_cap;
};

struct coins_record_header {
    int version;
    bool is_coinbase;
    unsigned int nmask_code;
    size_t num_avail;
    size_t live_outputs;
};

struct coins_record_output {
    uint32_t vout;
    int64_t value;
    uint64_t nsize;
    const uint8_t *script;
    size_t script_len;
    int version;
    bool is_coinbase;
};

struct coins_record_decode_result {
    int version;
    bool is_coinbase;
    int height;
    bool height_found;
    bool height_in_legacy_import_range;
    unsigned int nmask_code;
    size_t num_avail;
    size_t live_outputs;
    size_t outputs_emitted;
};

typedef bool (*coins_record_begin_fn)(const struct coins_record_header *hdr,
                                      void *ctx);
typedef bool (*coins_record_output_fn)(const struct coins_record_output *out,
                                       void *ctx);

struct coins_record_decode_ops {
    coins_record_begin_fn begin;
    coins_record_output_fn output;
};

struct coins_record_decode_options {
    enum coins_record_decode_mode mode;
    size_t max_outputs;
    struct coins_record_scratch *scratch;
};

const char *coins_record_decode_status_name(enum coins_record_decode_status st);

enum coins_record_decode_status coins_record_decode(
    const uint8_t *value,
    size_t value_len,
    const struct coins_record_decode_options *opts,
    const struct coins_record_decode_ops *ops,
    void *ctx,
    struct coins_record_decode_result *result);

bool coins_record_encode(const struct coins *cc, struct byte_stream *s);

void coins_record_scratch_free(struct coins_record_scratch *scratch);

#endif /* ZCL_STORAGE_COINS_RECORD_CODEC_H */
