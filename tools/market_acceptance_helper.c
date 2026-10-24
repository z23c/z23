/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * C23-only data helper for tools/dev/market_acceptance.sh.  The shell owns
 * process isolation and cleanup; this program owns JSON interpretation,
 * deterministic fixture bytes, SHA3 manifest roots, and typed assertions.
 * It never opens a wallet, node datadir, network socket, or private key.
 */

#include "json/json.h"
#include "sha3/sha3.h"
#include "base/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAH_INPUT_MAX (4u * 1024u * 1024u)
#define MAH_CHUNK_BYTES (50u * 1024u * 1024u)
#define MAH_BLOCK_BYTES 65536u
#define MAH_MANIFEST_CHUNKS_MAX 4096u

static int mah_fail(const char *message)
{
    fprintf(stderr, "market-acceptance-helper: %s\n", message);
    return 1;
}

static bool mah_parse_u64(const char *text, uint64_t *out)
{
    if (!text || !text[0] || text[0] == '-') return false;
    errno = 0;
    char *end = NULL;
    uintmax_t value = strtoumax(text, &end, 10);
    if (errno || !end || end == text || end[0] || value > UINT64_MAX)
        return false;
    *out = (uint64_t)value;
    return true;
}

static bool mah_amount_text_ok(const char *text)
{
    return text && text[0] && text[0] != '-' && text[0] != '+';
}

static bool mah_amount_whole_digit(int64_t *whole, int digit)
{
    if (*whole > (INT64_MAX - digit) / 10) return false;
    *whole = *whole * 10 + digit;
    return true;
}

static bool mah_amount_finish(int64_t whole, int64_t fraction,
                              unsigned decimals, int64_t *out)
{
    while (decimals++ < 8u) fraction *= 10;
    if (whole > (INT64_MAX - fraction) / 100000000LL) return false;
    *out = whole * 100000000LL + fraction;
    return true;
}

static bool mah_amount_zat(const char *text, int64_t *out)
{
    if (!mah_amount_text_ok(text)) return false;
    int64_t whole = 0, fraction = 0;
    unsigned decimals = 0;
    bool dot = false;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (*p == '.' && !dot) { dot = true; continue; }
        if (*p < '0' || *p > '9') return false;
        int digit = *p - '0';
        if (!dot) {
            if (!mah_amount_whole_digit(&whole, digit)) return false;
        } else {
            if (++decimals > 8u) return false;
            fraction = fraction * 10 + digit;
        }
    }
    if (dot && decimals == 0u) return false;
    return mah_amount_finish(whole, fraction, decimals, out);
}

static bool mah_read_stdin(char **raw_out, size_t *bytes_out)
{
    char *raw = zcl_malloc(MAH_INPUT_MAX + 1u, "market_helper.stdin");
    if (!raw) return false;
    size_t used = 0;
    while (used < MAH_INPUT_MAX) {
        ssize_t got = read(STDIN_FILENO, raw + used, MAH_INPUT_MAX - used);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) { free(raw); return false; }
        if (got == 0) break;
        used += (size_t)got;
    }
    if (used == MAH_INPUT_MAX) {
        char extra;
        ssize_t got;
        do { got = read(STDIN_FILENO, &extra, 1); } while (got < 0 && errno == EINTR);
        if (got != 0) { free(raw); return false; }
    }
    raw[used] = '\0';
    *raw_out = raw;
    *bytes_out = used;
    return true;
}

static bool mah_read_json(struct json_value *doc)
{
    char *raw = NULL;
    size_t bytes = 0;
    if (!mah_read_stdin(&raw, &bytes)) return false;
    bool ok = json_read(doc, raw, bytes);
    free(raw);
    return ok;
}

static const struct json_value *mah_member(const struct json_value *object,
                                           const char *key)
{
    return object && object->type == JSON_OBJ ? json_get(object, key) : NULL;
}

static const char *mah_string(const struct json_value *object, const char *key)
{
    const struct json_value *value = mah_member(object, key);
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool mah_streq(const struct json_value *object, const char *key,
                      const char *expected)
{
    const char *value = mah_string(object, key);
    return value && strcmp(value, expected) == 0;
}

static bool mah_bool(const struct json_value *object, const char *key,
                     bool expected)
{
    const struct json_value *value = mah_member(object, key);
    return value && value->type == JSON_BOOL &&
        json_get_bool(value) == expected;
}

static bool mah_int(const struct json_value *object, const char *key,
                    int64_t *out)
{
    const struct json_value *value = mah_member(object, key);
    if (!value || value->type != JSON_INT) return false;
    *out = json_get_int(value);
    return true;
}

static bool mah_int_equal(const struct json_value *object, const char *key,
                          int64_t expected)
{
    int64_t got = 0;
    return mah_int(object, key, &got) && got == expected;
}

static bool mah_int_positive(const struct json_value *object, const char *key)
{
    int64_t got = 0;
    return mah_int(object, key, &got) && got > 0;
}

static bool mah_hex64(const char *text)
{
    if (!text || strlen(text) != 64u) return false;
    bool nonzero = false;
    for (size_t i = 0; i < 64u; i++) {
        char c = text[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
        nonzero = nonzero || c != '0';
    }
    return nonzero;
}

static const char *mah_safe_build_reason(const char *message)
{
    static const char *const reasons[] = {
        "Invalid transaction arguments",
        "Invalid number of inputs or outputs",
        "Explicit input is not spendable",
        "Explicit input value overflow",
        "Duplicate explicit input",
        "Explicit output value overflow",
        "Explicit inputs do not cover outputs and fee",
        "Transaction allocation failed",
        "Cannot get change address",
        "Cannot determine input destination",
        "Private key not available",
        "Sighash computation failed",
        "Signing failed",
        "fee changed since planning",
    };
    for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++)
        if (message && strcmp(message, reasons[i]) == 0)
            return reasons[i];
    return "not_disclosed";
}

static const struct json_value *mah_data(const struct json_value *doc)
{
    return doc && doc->type == JSON_OBJ && mah_bool(doc, "ok", true)
        ? mah_member(doc, "data") : NULL;
}

static void mah_digest_hex(const uint8_t digest[32], char out[65])
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32u; i++) {
        out[i * 2u] = hex[digest[i] >> 4u];
        out[i * 2u + 1u] = hex[digest[i] & 15u];
    }
    out[64] = '\0';
}

static bool mah_write_all(int fd, const uint8_t *bytes, size_t size)
{
    size_t written = 0;
    while (written < size) {
        ssize_t rc = write(fd, bytes + written, size - written);
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0) return false;
        written += (size_t)rc;
    }
    return true;
}

static bool mah_fixture_write_chunk(int fd, uint8_t *block, uint32_t index,
                                    uint8_t digest[32])
{
    for (size_t i = 0; i < MAH_BLOCK_BYTES; i++)
        block[i] = (uint8_t)((index * 131u + i * 7u) & 0xffu);
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    bool ok = true;
    for (size_t offset = 0; ok && offset < MAH_CHUNK_BYTES;
         offset += MAH_BLOCK_BYTES) {
        ok = mah_write_all(fd, block, MAH_BLOCK_BYTES);
        if (ok) sha3_256_write(&sha, block, MAH_BLOCK_BYTES);
    }
    if (ok) sha3_256_finalize(&sha, digest);
    return ok;
}

static bool mah_fixture_write_tail(int fd, uint8_t *block, uint64_t tail,
                                   uint8_t digest[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    bool ok = true;
    uint64_t offset = 0;
    while (ok && offset < tail) {
        size_t take = tail - offset > MAH_BLOCK_BYTES
            ? MAH_BLOCK_BYTES : (size_t)(tail - offset);
        for (size_t i = 0; i < take; i++)
            block[i] = (uint8_t)((5u + (offset + i) * 11u) & 0xffu);
        ok = mah_write_all(fd, block, take);
        if (ok) sha3_256_write(&sha, block, take);
        offset += take;
    }
    if (ok) sha3_256_finalize(&sha, digest);
    return ok;
}

static bool mah_fixture_create(const char *path, uint64_t price,
                               uint64_t tail, uint64_t *size_out,
                               char root_out[65], uint64_t *total_out)
{
    if (tail == 0 || tail > MAH_CHUNK_BYTES || price == 0) return false;
    uint64_t size = 2u * (uint64_t)MAH_CHUNK_BYTES + tail;
    uint64_t mb = 1024u * 1024u;
    uint64_t whole = size / mb, rem = size % mb;
    if (price > UINT64_MAX / (whole + 2u)) return false;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                  0600);
    if (fd < 0) return false;
    uint8_t *block = zcl_malloc(MAH_BLOCK_BYTES, "market_helper.fixture");
    uint8_t digests[3][32];
    bool ok = block != NULL;
    for (uint32_t index = 0; ok && index < 2u; index++)
        ok = mah_fixture_write_chunk(fd, block, index, digests[index]);
    if (ok) ok = mah_fixture_write_tail(fd, block, tail, digests[2]);
    if (ok && fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    free(block);
    if (!ok) { (void)unlink(path); return false; }

    uint8_t manifest[32];
    sha3_256((const uint8_t *)digests, sizeof(digests), manifest);
    mah_digest_hex(manifest, root_out);
    uint64_t price_whole = price / mb, price_rem = price % mb;
    *size_out = size;
    *total_out = whole * price + rem * price_whole +
        (rem * price_rem + mb - 1u) / mb;
    return true;
}

static bool mah_manifest_close_chunk(struct sha3_256_ctx *sha,
                                     uint8_t *digests, size_t *chunks)
{
    if (*chunks == MAH_MANIFEST_CHUNKS_MAX) return false;
    sha3_256_finalize(sha, digests + *chunks * 32u);
    (*chunks)++;
    return true;
}

static bool mah_manifest_read_chunks(int fd, uint8_t *buffer, uint8_t *digests,
                                     size_t *chunks, size_t *in_chunk,
                                     struct sha3_256_ctx *sha)
{
    while (true) {
        size_t remaining = MAH_CHUNK_BYTES - *in_chunk;
        size_t want = remaining < MAH_BLOCK_BYTES ? remaining : MAH_BLOCK_BYTES;
        ssize_t got = read(fd, buffer, want);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) return false;
        if (got == 0) return true;
        sha3_256_write(sha, buffer, (size_t)got);
        *in_chunk += (size_t)got;
        if (*in_chunk == MAH_CHUNK_BYTES) {
            if (!mah_manifest_close_chunk(sha, digests, chunks)) return false;
            *in_chunk = 0;
            sha3_256_init(sha);
        }
    }
}

static bool mah_file_manifest_root(const char *path, char root_out[65])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    uint8_t *buffer = zcl_malloc(MAH_BLOCK_BYTES, "market_helper.file_buffer");
    uint8_t *digests = zcl_calloc(MAH_MANIFEST_CHUNKS_MAX, 32u,
                                  "market_helper.manifest");
    bool ok = buffer && digests;
    size_t chunks = 0, in_chunk = 0;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    if (ok) ok = mah_manifest_read_chunks(fd, buffer, digests, &chunks,
                                          &in_chunk, &sha);
    if (ok && in_chunk > 0)
        ok = mah_manifest_close_chunk(&sha, digests, &chunks);
    if (close(fd) != 0) ok = false;
    if (ok && chunks == 0) ok = false;
    if (ok) {
        uint8_t root[32];
        sha3_256(digests, chunks * 32u, root);
        mah_digest_hex(root, root_out);
    }
    free(digests);
    free(buffer);
    return ok;
}

static const struct json_value *mah_path(const struct json_value *root,
                                         const char *path)
{
    char copy[256];
    if (!path || strlen(path) >= sizeof(copy)) return NULL;
    (void)snprintf(copy, sizeof(copy), "%s", path);
    const struct json_value *current = root;
    char *save = NULL;
    for (char *part = strtok_r(copy, ".", &save); part;
         part = strtok_r(NULL, ".", &save)) {
        if (current->type == JSON_OBJ) current = json_get(current, part);
        else if (current->type == JSON_ARR) {
            uint64_t index = 0;
            if (!mah_parse_u64(part, &index) || index > SIZE_MAX) return NULL;
            current = json_at(current, (size_t)index);
        } else return NULL;
        if (!current) return NULL;
    }
    return current;
}

static bool mah_print_value(const struct json_value *value)
{
    if (!value) return false;
    switch (value->type) {
    case JSON_STR: printf("%s\n", json_get_str(value)); return true;
    case JSON_BOOL: printf("%s\n", json_get_bool(value) ? "True" : "False"); return true;
    case JSON_INT: printf("%" PRId64 "\n", json_get_int(value)); return true;
    case JSON_REAL: printf("%.17g\n", json_get_real(value)); return true;
    case JSON_NULL: printf("null\n"); return true;
    case JSON_ARR:
    case JSON_OBJ: {
        size_t bytes = json_write(value, NULL, 0);
        char *wire = zcl_malloc(bytes + 1u, "market_helper.json_wire");
        if (!wire) return false;
        bool ok = json_write(value, wire, bytes + 1u) == bytes;
        if (ok) printf("%s\n", wire);
        free(wire);
        return ok;
    }
    }
    return false;
}

static bool mah_offer_plan_sizes_ok(const struct json_value *data,
                                    int64_t size, int64_t chunks,
                                    int64_t total)
{
    return mah_int_equal(data, "size_bytes", size) &&
        mah_int_equal(data, "num_chunks", chunks) &&
        mah_int_equal(data, "total_zat", total) &&
        mah_int_positive(data, "price_per_mb_zat");
}

static bool mah_expect_offer_plan(const struct json_value *doc,
                                  const char *root, int64_t size,
                                  int64_t chunks, int64_t total)
{
    const struct json_value *data = mah_data(doc);
    return data && mah_streq(data, "stage", "plan") &&
        mah_bool(data, "committed", false) &&
        mah_bool(data, "spends_funds", false) &&
        mah_streq(data, "root_hash", root) &&
        mah_offer_plan_sizes_ok(data, size, chunks, total) &&
        mah_member(data, "commit_input") && !mah_member(data, "offer_id") &&
        !mah_member(data, "seller_pubkey");
}

static const char *mah_expect_offer_commit(const struct json_value *doc,
                                           const char *root)
{
    const struct json_value *data = mah_data(doc);
    const char *offer = mah_string(data, "offer_id");
    const char *seller = mah_string(data, "seller_pubkey");
    return data && mah_streq(data, "stage", "committed") &&
        mah_bool(data, "committed", true) &&
        mah_bool(data, "idempotent_replay", false) &&
        mah_bool(data, "announced", true) &&
        mah_streq(data, "root_hash", root) &&
        mah_hex64(offer) && seller && strlen(seller) == 64u ? offer : NULL;
}

static bool mah_offer_view_header(const struct json_value *view,
                                  const char *profile, bool override,
                                  int64_t *offer_count, int64_t *hidden_count)
{
    return view && mah_streq(view, "profile", profile) &&
        mah_bool(view, "profile_override", override) &&
        mah_int(view, "offer_count", offer_count) &&
        mah_int(view, "hidden_count", hidden_count);
}

static const struct json_value *mah_offer_rows(const struct json_value *view,
                                               int64_t offer_count)
{
    const struct json_value *rows = mah_member(view, "offers");
    return rows && rows->type == JSON_ARR &&
        (uint64_t)offer_count == rows->num_children ? rows : NULL;
}

/* Counts the rows whose offer_id equals `offer`; `match`, when set, receives
 * the last such row. */
static size_t mah_count_offer_rows(const struct json_value *rows,
                                   const char *offer,
                                   const struct json_value **match)
{
    size_t count = 0;
    for (size_t i = 0; i < rows->num_children; i++) {
        const struct json_value *row = json_at(rows, i);
        const char *id = mah_string(row, "offer_id");
        if (id && strcmp(id, offer) == 0) {
            if (match) *match = row;
            count++;
        }
    }
    return count;
}

static bool mah_buyer_row_ok(const struct json_value *match, const char *root,
                             int64_t price, int64_t chunks, int64_t total)
{
    return match && mah_streq(match, "root_hash", root) &&
        mah_int_equal(match, "price_per_mb_zat", price) &&
        mah_int_equal(match, "num_chunks", chunks) &&
        mah_int_equal(match, "total_cost_zat", total) &&
        mah_bool(match, "authenticated", true) &&
        mah_int_positive(match, "peer_port");
}

static bool mah_expect_buyer_entry(const struct json_value *doc,
                                   const char *offer, const char *root,
                                   int64_t price, int64_t chunks, int64_t total)
{
    const struct json_value *view = mah_data(doc);
    int64_t offer_count = -1, hidden_count = -1;
    if (!mah_offer_view_header(view, "open-view", true, &offer_count,
                               &hidden_count) ||
        offer_count < 1 || hidden_count != 0)
        return false;
    const struct json_value *rows = mah_offer_rows(view, offer_count);
    if (!rows) return false;
    const struct json_value *match = NULL;
    size_t count = mah_count_offer_rows(rows, offer, &match);
    return count == 1 && mah_buyer_row_ok(match, root, price, chunks, total);
}

static bool mah_expect_market_hidden(const struct json_value *doc,
                                     const char *offer)
{
    const struct json_value *view = mah_data(doc);
    int64_t offer_count = -1, hidden_count = -1;
    if (!mah_offer_view_header(view, "general-audience.v1", false,
                               &offer_count, &hidden_count) ||
        offer_count < 0 || hidden_count < 1)
        return false;
    const struct json_value *rows = mah_offer_rows(view, offer_count);
    return rows && mah_count_offer_rows(rows, offer, NULL) == 0;
}

static bool mah_expect_market_empty(const struct json_value *doc)
{
    int64_t offers = -1, hidden = -1;
    const struct json_value *rows = mah_member(doc, "offers");
    return doc && doc->type == JSON_OBJ &&
        mah_string(doc, "profile") &&
        rows && rows->type == JSON_ARR && rows->num_children == 0u &&
        mah_int(doc, "offer_count", &offers) && offers == 0 &&
        mah_int(doc, "hidden_count", &hidden) && hidden == 0;
}

static bool mah_purchase_plan_flags_ok(const struct json_value *data,
                                       const char *offer)
{
    return mah_streq(data, "stage", "plan") &&
        mah_bool(data, "committed", false) &&
        mah_bool(data, "spends_funds", false) &&
        mah_streq(data, "offer_id", offer) &&
        mah_streq(data, "state", "planned") &&
        mah_bool(data, "idempotent_replay", false) &&
        mah_member(data, "commit_input");
}

static bool mah_purchase_plan_amounts_ok(const struct json_value *data,
                                         int64_t total)
{
    int64_t amount = 0, fee = 0, reserved = 0;
    return mah_int(data, "amount_zat", &amount) && amount == total &&
        mah_int(data, "maximum_fee_zat", &fee) && fee > 0 &&
        mah_int(data, "reserved_zat", &reserved) && reserved == amount + fee;
}

static const char *mah_expect_purchase_plan(const struct json_value *doc,
                                            const char *offer, int64_t total)
{
    const struct json_value *data = mah_data(doc);
    const char *plan = mah_string(data, "plan_id");
    return data && mah_purchase_plan_flags_ok(data, offer) &&
        mah_purchase_plan_amounts_ok(data, total) &&
        mah_int_equal(data, "chunk_start", 0) &&
        mah_int_positive(data, "chunks_paid") && mah_hex64(plan) ? plan : NULL;
}

static const char *mah_expect_purchase_commit(const struct json_value *doc)
{
    const struct json_value *data = mah_data(doc);
    const char *txid = mah_string(data, "txid");
    return data && mah_streq(data, "stage", "committed") &&
        mah_bool(data, "committed", true) &&
        mah_bool(data, "spends_funds", true) &&
        mah_bool(data, "idempotent_replay", false) &&
        mah_bool(data, "payment_notification_queued", true) &&
        mah_streq(data, "state", "mempool_accepted") &&
        mah_hex64(txid) && mah_hex64(mah_string(data, "claim_id")) ? txid : NULL;
}

static bool mah_expect_early_refusal(const struct json_value *doc)
{
    const struct json_value *error = mah_member(doc, "error");
    const char *code = mah_string(error, "code");
    const char *message = mah_string(error, "message");
    return doc && doc->type == JSON_OBJ && mah_bool(doc, "ok", false) &&
        code && strcmp(code, "DELIVERY_NOT_READY") == 0 && message &&
        (strstr(message, "PENDING") || strstr(message, "UNKNOWN"));
}

static bool mah_expect_purchase_status(const struct json_value *doc,
                                       const char *txid)
{
    const struct json_value *data = mah_data(doc);
    return data && mah_streq(data, "state", "confirmed") &&
        mah_streq(data, "txid", txid) &&
        mah_hex64(mah_string(data, "claim_id"));
}

static bool mah_expect_retrieve(const struct json_value *doc,
                                int64_t size, int64_t chunks)
{
    const struct json_value *data = mah_data(doc);
    int64_t got = 0, total = 0, bytes = 0, size_bytes = 0;
    return data && mah_streq(data, "stage", "retrieved") &&
        mah_streq(data, "download_state", "complete") &&
        mah_bool(data, "destination_published", true) &&
        mah_int(data, "chunks_received", &got) && got == chunks &&
        mah_int(data, "num_chunks", &total) && total == chunks &&
        mah_int(data, "bytes_received", &bytes) && bytes == size &&
        mah_int(data, "size_bytes", &size_bytes) && size_bytes == size;
}

static bool mah_claim_row(const struct json_value *data,
                          const struct json_value **columns_out,
                          const struct json_value **row_out)
{
    const struct json_value *columns = mah_member(data, "columns");
    const struct json_value *rows = mah_member(data, "rows");
    if (!columns || columns->type != JSON_ARR || !rows || rows->type != JSON_ARR ||
        rows->num_children != 1u) return false;
    const struct json_value *row = json_at(rows, 0);
    if (!row || row->type != JSON_ARR || row->num_children != columns->num_children)
        return false;
    *columns_out = columns;
    *row_out = row;
    return true;
}

static bool mah_claim_locate(const struct json_value *columns,
                             const struct json_value *row,
                             const struct json_value **status,
                             const struct json_value **confirmations,
                             const struct json_value **height)
{
    for (size_t i = 0; i < columns->num_children; i++) {
        const char *name = json_get_str(json_at(columns, i));
        if (!name) return false;
        if (strcmp(name, "status") == 0) *status = json_at(row, i);
        else if (strcmp(name, "confirmations") == 0) *confirmations = json_at(row, i);
        else if (strcmp(name, "block_height") == 0) *height = json_at(row, i);
    }
    return true;
}

static bool mah_claim_values_ok(const struct json_value *status,
                                const struct json_value *confirmations,
                                const struct json_value *height,
                                int64_t want_height)
{
    return status && status->type == JSON_STR &&
        strcmp(json_get_str(status), "CONFIRMED") == 0 &&
        confirmations && confirmations->type == JSON_INT &&
        json_get_int(confirmations) >= 1 && height && height->type == JSON_INT &&
        json_get_int(height) == want_height;
}

static bool mah_expect_claim(const struct json_value *doc, int64_t want_height)
{
    const struct json_value *data = mah_data(doc);
    const struct json_value *columns = NULL, *row = NULL;
    const struct json_value *status = NULL, *confirmations = NULL, *height = NULL;
    return mah_claim_row(data, &columns, &row) &&
        mah_claim_locate(columns, row, &status, &confirmations, &height) &&
        mah_claim_values_ok(status, confirmations, height, want_height);
}

static bool mah_expect_replay(const struct json_value *doc,
                              const char *field, const char *expected,
                              bool require_committed)
{
    const struct json_value *data = mah_data(doc);
    return data && mah_bool(data, "idempotent_replay", true) &&
        mah_streq(data, field, expected) &&
        (!require_committed ||
         (mah_streq(data, "stage", "committed") &&
          mah_bool(data, "committed", true)));
}

static bool mah_address_shape(const char *address, bool shielded)
{
    if (!address || strlen(address) < 20u) return false;
    return shielded ? address[0] == 'z' : address[0] != 'z';
}

static bool mah_intent_plan_head_ok(const struct json_value *data,
                                    const char *route, bool replay)
{
    return data && mah_bool(data, "ok", true) &&
        mah_streq(data, "state", "planned") &&
        mah_streq(data, "wallet_scope", "dev") &&
        mah_streq(data, "route", route) &&
        mah_bool(data, "idempotent_plan", replay) &&
        mah_hex64(mah_string(data, "plan_id")) &&
        mah_hex64(mah_string(data, "digest")) &&
        mah_hex64(mah_string(data, "money_snapshot_root"));
}

static bool mah_amount_positive(const char *text, int64_t *out)
{
    return mah_amount_zat(text, out) && *out > 0;
}

static bool mah_intent_plan_amounts_ok(const struct json_value *data,
                                       const char *expected_amount)
{
    const char *recipient = mah_string(data, "recipient_value");
    const char *fee = mah_string(data, "maximum_fee");
    const char *reserved = mah_string(data, "reserved");
    int64_t recipient_zat = 0, fee_zat = 0, reserved_zat = 0;
    return mah_streq(data, "recipient_value", expected_amount) &&
        recipient && fee && reserved &&
        mah_amount_positive(recipient, &recipient_zat) &&
        mah_amount_positive(fee, &fee_zat) &&
        mah_amount_zat(reserved, &reserved_zat) &&
        recipient_zat <= INT64_MAX - fee_zat &&
        reserved_zat == recipient_zat + fee_zat;
}

static bool mah_intent_plan_effect(const struct json_value *data,
                                   const char *expected_amount,
                                   const char **to_out)
{
    const struct json_value *effects = mah_member(data, "effects");
    if (!effects || effects->type != JSON_ARR || effects->num_children != 1u)
        return false;
    const struct json_value *effect = json_at(effects, 0);
    *to_out = mah_string(effect, "to");
    return mah_streq(effect, "asset", "ZCL") &&
        mah_streq(effect, "amount", expected_amount);
}

static bool mah_intent_route_ok(const char *route, const char *from,
                                const char *to)
{
    bool source_z = from && mah_address_shape(from, true);
    bool recipient_z = mah_address_shape(to, true);
    if (strcmp(route, "transparent") == 0)
        return !(from || source_z || recipient_z);
    if (strcmp(route, "shield") == 0)
        return from && !source_z && recipient_z;
    if (strcmp(route, "private") == 0)
        return source_z && recipient_z;
    if (strcmp(route, "unshield") == 0)
        return source_z && !recipient_z;
    return true;
}

static const char *mah_expect_intent_plan(const struct json_value *doc,
                                          const char *route,
                                          const char *expected_amount,
                                          bool replay)
{
    const struct json_value *data = mah_data(doc);
    const char *to = NULL;
    if (!mah_intent_plan_head_ok(data, route, replay) ||
        !mah_intent_plan_amounts_ok(data, expected_amount) ||
        !mah_intent_plan_effect(data, expected_amount, &to) ||
        !mah_intent_route_ok(route, mah_string(data, "from"), to))
        return NULL;
    return mah_string(data, "plan_id");
}

static const char *mah_expect_intent_commit(const struct json_value *doc,
                                            const char *plan,
                                            const char *state, bool replay)
{
    const struct json_value *data = mah_data(doc);
    const char *txid = mah_string(data, "txid");
    bool inner_ok = data && mah_bool(data, "ok", true);
    bool plan_ok = data && mah_streq(data, "plan_id", plan);
    bool scope_ok = data && mah_streq(data, "wallet_scope", "dev");
    bool state_ok = data && mah_streq(data, "state", state);
    bool txid_ok = mah_hex64(txid);
    bool replay_ok = data && mah_bool(data, "idempotent_replay", replay);
    if (!data || !inner_ok || !plan_ok || !scope_ok || !state_ok ||
        !txid_ok || !replay_ok) {
        const struct json_value *error = mah_member(doc, "error");
        const char *code = mah_string(error, "code");
        const char *message = mah_string(error, "message");
        const char *got_state = mah_string(data, "state");
        fprintf(stderr,
                "market-acceptance-helper: intent commit contract "
                "outer_data=%d inner_ok=%d plan=%d scope=%d state=%s "
                "state_match=%d txid_shape=%d replay=%d error_code=%s "
                "build_reason=%s\n",
                data != NULL, inner_ok, plan_ok, scope_ok,
                got_state ? got_state : "absent", state_ok, txid_ok,
                replay_ok, code ? code : "none",
                mah_safe_build_reason(message));
        return NULL;
    }
    return txid;
}

static bool mah_expect_intent_status(const struct json_value *doc,
                                     const char *plan, const char *txid,
                                     const char *state)
{
    const struct json_value *data = mah_data(doc);
    int64_t confirmations = -1;
    if (!data || !mah_bool(data, "ok", true) ||
        !mah_streq(data, "plan_id", plan) ||
        !mah_streq(data, "txid", txid) ||
        !mah_streq(data, "state", state) ||
        !mah_int(data, "confirmations", &confirmations))
        return false;
    if (strcmp(state, "confirmed") == 0)
        return confirmations >= 1 &&
            mah_int(data, "confirmed_height", &confirmations) &&
            confirmations >= 0 &&
            mah_hex64(mah_string(data, "confirmed_block_hash"));
    return confirmations == 0;
}

static bool mah_expect_intent_error(const struct json_value *doc,
                                    const char *code)
{
    const struct json_value *error = mah_member(doc, "error");
    return doc && doc->type == JSON_OBJ && mah_bool(doc, "ok", false) &&
        error && error->type == JSON_OBJ && mah_streq(error, "code", code) &&
        mah_member(error, "retryable") &&
        mah_member(error, "human_action_required") &&
        mah_string(error, "message");
}

static bool mah_expect_chain_tx(const struct json_value *doc,
                                const char *txid, bool confirmed)
{
    const struct json_value *data = mah_data(doc);
    const struct json_value *confirmations = mah_member(data, "confirmations");
    if (!data || !mah_streq(data, "txid", txid)) return false;
    if (!confirmed)
        return !confirmations ||
            (confirmations->type == JSON_INT && json_get_int(confirmations) == 0);
    return confirmations && confirmations->type == JSON_INT &&
        json_get_int(confirmations) >= 1;
}

static bool mah_arg_i64(const char *text, int64_t *out)
{
    uint64_t value = 0;
    if (!mah_parse_u64(text, &value) || value > INT64_MAX) return false;
    *out = (int64_t)value;
    return true;
}

/* One `json` subcommand: validates its arguments against the document and
 * reports success; output, when set, is printed on success or failure. */
struct mah_json_ctx {
    const struct json_value *doc;
    char **argv;
    const char *output;
};

struct mah_json_command_row {
    const char *name;
    int argc;
    bool (*run)(struct mah_json_ctx *ctx);
};

static bool mah_cmd_get(struct mah_json_ctx *c)
{
    return mah_print_value(mah_path(c->doc, c->argv[2]));
}

static bool mah_cmd_rpc_result(struct mah_json_ctx *c)
{
    const struct json_value *error = mah_member(c->doc, "error");
    return (!error || error->type == JSON_NULL) &&
        mah_print_value(mah_member(c->doc, "result"));
}

static bool mah_cmd_offer_plan(struct mah_json_ctx *c)
{
    int64_t size, chunks, total;
    return mah_arg_i64(c->argv[3], &size) && mah_arg_i64(c->argv[4], &chunks) &&
        mah_arg_i64(c->argv[5], &total) &&
        mah_expect_offer_plan(c->doc, c->argv[2], size, chunks, total);
}

static bool mah_cmd_offer_commit(struct mah_json_ctx *c)
{
    c->output = mah_expect_offer_commit(c->doc, c->argv[2]);
    return c->output != NULL;
}

static bool mah_cmd_buyer_entry(struct mah_json_ctx *c)
{
    int64_t price, chunks, total;
    return mah_arg_i64(c->argv[4], &price) &&
        mah_arg_i64(c->argv[5], &chunks) && mah_arg_i64(c->argv[6], &total) &&
        mah_expect_buyer_entry(c->doc, c->argv[2], c->argv[3], price, chunks,
                               total);
}

static bool mah_cmd_market_empty(struct mah_json_ctx *c)
{
    return mah_expect_market_empty(c->doc);
}

static bool mah_cmd_market_hidden(struct mah_json_ctx *c)
{
    return mah_expect_market_hidden(c->doc, c->argv[2]);
}

static bool mah_cmd_purchase_plan(struct mah_json_ctx *c)
{
    int64_t total;
    if (mah_arg_i64(c->argv[3], &total))
        c->output = mah_expect_purchase_plan(c->doc, c->argv[2], total);
    return c->output != NULL;
}

static bool mah_cmd_purchase_commit(struct mah_json_ctx *c)
{
    c->output = mah_expect_purchase_commit(c->doc);
    return c->output != NULL;
}

static bool mah_cmd_early_refusal(struct mah_json_ctx *c)
{
    return mah_expect_early_refusal(c->doc);
}

static bool mah_cmd_purchase_status(struct mah_json_ctx *c)
{
    return mah_expect_purchase_status(c->doc, c->argv[2]);
}

static bool mah_cmd_retrieve(struct mah_json_ctx *c)
{
    int64_t size, chunks;
    return mah_arg_i64(c->argv[2], &size) && mah_arg_i64(c->argv[3], &chunks) &&
        mah_expect_retrieve(c->doc, size, chunks);
}

static bool mah_cmd_claim(struct mah_json_ctx *c)
{
    int64_t height;
    return mah_arg_i64(c->argv[2], &height) && mah_expect_claim(c->doc, height);
}

static bool mah_cmd_recommit(struct mah_json_ctx *c)
{
    return mah_expect_replay(c->doc, "txid", c->argv[2], false);
}

static bool mah_cmd_replan(struct mah_json_ctx *c)
{
    return mah_expect_replay(c->doc, "plan_id", c->argv[2], false);
}

static bool mah_cmd_reoffer(struct mah_json_ctx *c)
{
    return mah_expect_replay(c->doc, "offer_id", c->argv[2], true);
}

static bool mah_cmd_intent_plan(struct mah_json_ctx *c)
{
    bool replay = strcmp(c->argv[4], "replay") == 0;
    if (replay || strcmp(c->argv[4], "fresh") == 0)
        c->output = mah_expect_intent_plan(c->doc, c->argv[2], c->argv[3],
                                           replay);
    return c->output != NULL;
}

static bool mah_cmd_intent_commit(struct mah_json_ctx *c)
{
    bool replay = strcmp(c->argv[4], "replay") == 0;
    if (replay || strcmp(c->argv[4], "fresh") == 0)
        c->output = mah_expect_intent_commit(c->doc, c->argv[2], c->argv[3],
                                             replay);
    return c->output != NULL;
}

static bool mah_cmd_intent_status(struct mah_json_ctx *c)
{
    return mah_expect_intent_status(c->doc, c->argv[2], c->argv[3],
                                    c->argv[4]);
}

static bool mah_cmd_intent_error(struct mah_json_ctx *c)
{
    return mah_expect_intent_error(c->doc, c->argv[2]);
}

static bool mah_cmd_amount(struct mah_json_ctx *c)
{
    const struct json_value *value = mah_path(c->doc, c->argv[2]);
    int64_t amount = 0;
    if (!value || value->type != JSON_STR ||
        !mah_amount_zat(json_get_str(value), &amount))
        return false;
    printf("%" PRId64 "\n", amount);
    return true;
}

static bool mah_cmd_address(struct mah_json_ctx *c)
{
    const struct json_value *data = mah_data(c->doc);
    const char *address = mah_string(data, "address");
    bool shielded = strcmp(c->argv[2], "sapling") == 0;
    if ((!shielded && strcmp(c->argv[2], "transparent") != 0) ||
        !mah_address_shape(address, shielded))
        return false;
    c->output = address;
    return true;
}

static bool mah_cmd_mempool_at_least(struct mah_json_ctx *c)
{
    int64_t want = 0, size = -1;
    const struct json_value *data = mah_data(c->doc);
    return mah_arg_i64(c->argv[2], &want) && mah_int(data, "size", &size) &&
        size >= want;
}

static bool mah_cmd_chain_tx(struct mah_json_ctx *c)
{
    bool confirmed = strcmp(c->argv[3], "confirmed") == 0;
    return (confirmed || strcmp(c->argv[3], "mempool") == 0) &&
        mah_expect_chain_tx(c->doc, c->argv[2], confirmed);
}

static bool mah_cmd_intent_list_at_least(struct mah_json_ctx *c)
{
    int64_t want = 0, count = -1;
    const struct json_value *data = mah_data(c->doc);
    return mah_arg_i64(c->argv[2], &want) && mah_bool(data, "ok", true) &&
        mah_int(data, "count", &count) && count >= want;
}

static const struct mah_json_command_row k_mah_json_commands[] = {
    {"get", 3, mah_cmd_get},
    {"rpc-result", 2, mah_cmd_rpc_result},
    {"offer-plan", 6, mah_cmd_offer_plan},
    {"offer-commit", 3, mah_cmd_offer_commit},
    {"buyer-entry", 7, mah_cmd_buyer_entry},
    {"market-empty", 2, mah_cmd_market_empty},
    {"market-hidden", 3, mah_cmd_market_hidden},
    {"purchase-plan", 4, mah_cmd_purchase_plan},
    {"purchase-commit", 2, mah_cmd_purchase_commit},
    {"early-refusal", 2, mah_cmd_early_refusal},
    {"purchase-status", 3, mah_cmd_purchase_status},
    {"retrieve", 4, mah_cmd_retrieve},
    {"claim", 3, mah_cmd_claim},
    {"recommit", 3, mah_cmd_recommit},
    {"replan", 3, mah_cmd_replan},
    {"reoffer", 3, mah_cmd_reoffer},
    {"intent-plan", 5, mah_cmd_intent_plan},
    {"intent-commit", 5, mah_cmd_intent_commit},
    {"intent-status", 5, mah_cmd_intent_status},
    {"intent-error", 3, mah_cmd_intent_error},
    {"amount", 3, mah_cmd_amount},
    {"address", 3, mah_cmd_address},
    {"mempool-at-least", 3, mah_cmd_mempool_at_least},
    {"chain-tx", 4, mah_cmd_chain_tx},
    {"intent-list-at-least", 3, mah_cmd_intent_list_at_least},
};

static int mah_json_command(int argc, char **argv)
{
    struct json_value doc;
    json_init(&doc);
    if (!mah_read_json(&doc)) { json_free(&doc); return mah_fail("invalid JSON input"); }
    struct mah_json_ctx ctx = {.doc = &doc, .argv = argv};
    bool ok = false;
    for (size_t i = 0; i < sizeof(k_mah_json_commands) /
                           sizeof(k_mah_json_commands[0]); i++) {
        const struct mah_json_command_row *row = &k_mah_json_commands[i];
        if (strcmp(argv[1], row->name) != 0 || argc != row->argc) continue;
        ok = row->run(&ctx);
        break;
    }
    if (ctx.output) printf("%s\n", ctx.output);
    json_free(&doc);
    return ok ? 0 : mah_fail("JSON contract mismatch");
}

static int mah_selftest(void)
{
    const char sample[] = "{\"result\":{\"ready\":true,\"n\":7}}";
    struct json_value doc;
    json_init(&doc);
    bool ok = json_read(&doc, sample, sizeof(sample) - 1u) &&
        mah_path(&doc, "result.ready") &&
        json_get_bool(mah_path(&doc, "result.ready")) &&
        json_get_int(mah_path(&doc, "result.n")) == 7 &&
        mah_hex64("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    json_free(&doc);
    if (!ok) return mah_fail("selftest failed");
    puts("market-acceptance-helper: PASS");
    return 0;
}

static int mah_fixture_command(char **argv)
{
    uint64_t price = 0, tail = 0, size = 0, total = 0;
    char root[65];
    if (!mah_parse_u64(argv[3], &price) || !mah_parse_u64(argv[4], &tail) ||
        !mah_fixture_create(argv[2], price, tail, &size, root, &total))
        return mah_fail("fixture creation failed");
    printf("%" PRIu64 " %s %" PRIu64 "\n", size, root, total);
    return 0;
}

static int mah_reverse_hex_command(const char *text)
{
    if (!mah_hex64(text)) return mah_fail("invalid 64-byte-order hex");
    for (int i = 62; i >= 0; i -= 2) {
        putchar(text[i]);
        putchar(text[i + 1]);
    }
    putchar('\n');
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        return mah_selftest();
    if (argc == 5 && strcmp(argv[1], "fixture-create") == 0)
        return mah_fixture_command(argv);
    if (argc == 3 && strcmp(argv[1], "file-root") == 0) {
        char root[65];
        if (!mah_file_manifest_root(argv[2], root))
            return mah_fail("file manifest verification failed");
        printf("%s\n", root);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "reverse-hex") == 0)
        return mah_reverse_hex_command(argv[2]);
    if (argc >= 2) return mah_json_command(argc, argv);
    return mah_fail("command required");
}
