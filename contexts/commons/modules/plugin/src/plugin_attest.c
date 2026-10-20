/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the independent-builder attestation record: canonical encoding,
 * total parsing, Ed25519 signing and verification, and the builder side that
 * hashes an image and writes the record. The multi-builder verdict is
 * plugin_attest_verify.c. */

#include "plugin_internal.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "crypto/ed25519.h"
#include "plugin/plugin_attest.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define PA_SCHEMA "z23.plugin.attest.v1"

enum pa_kind { PA_NAME, PA_VERSION, PA_KEY, PA_SIG, PA_IMAGE, PA_TOOLCHAIN };

static const struct {
    const char *lead;
    size_t offset;
    size_t cap;
    enum pa_kind kind;
} pa_fields[] = {
    { "{\"schema\":\"" PA_SCHEMA "\",\"name\":\"", offsetof(struct plugin_attest_record, name),
      PLUGIN_NAME_MAX, PA_NAME },
    { "\",\"version\":\"", offsetof(struct plugin_attest_record, version),
      PLUGIN_VERSION_MAX, PA_VERSION },
    { "\",\"source_root\":\"", offsetof(struct plugin_attest_record, source_root),
      PLUGIN_ATTEST_HEX_KEY, PA_KEY },
    { "\",\"toolchain\":\"", offsetof(struct plugin_attest_record, toolchain),
      PLUGIN_ATTEST_TOOLCHAIN_MAX, PA_TOOLCHAIN },
    { "\",\"image_sha3_512\":\"", offsetof(struct plugin_attest_record, image),
      PLUGIN_HEX_SHA3_512, PA_IMAGE },
    { "\",\"builder_key\":\"", offsetof(struct plugin_attest_record, builder_key),
      PLUGIN_ATTEST_HEX_KEY, PA_KEY },
    { "\",\"signature\":\"", offsetof(struct plugin_attest_record, signature),
      PLUGIN_ATTEST_HEX_SIG, PA_SIG },
};
enum { PA_FIELD_COUNT = sizeof(pa_fields) / sizeof(pa_fields[0]), PA_SIGNED_FIELDS = 6 };
#define PA_TAIL "\"}\n"

static const struct {
    const char *code;
    const char *next_action;
} pa_text[] = {
    [PLUGIN_ATTEST_OK] = { "PLUGIN_ATTEST_OK", "" },
    [PLUGIN_ATTEST_ARGUMENT] = { "PLUGIN_ATTEST_ARGUMENT",
        "pass the documented arguments: z23 discover describe plugin.attest" },
    [PLUGIN_ATTEST_UPSTREAM] = { "PLUGIN_ATTEST_UPSTREAM",
        "fix the named file or key, then retry" },
    [PLUGIN_ATTEST_IO] = { "PLUGIN_ATTEST_IO",
        "check the directory is writable and has space, then retry" },
    [PLUGIN_ATTEST_MALFORMED] = { "PLUGIN_ATTEST_MALFORMED",
        "regenerate the attestation with z23 plugin attest; hand-edited records are refused" },
    [PLUGIN_ATTEST_SIG_BAD] = { "PLUGIN_ATTEST_SIG_BAD",
        "discard the attestation: its signature does not verify under its builder key" },
    [PLUGIN_ATTEST_PINS_MALFORMED] = { "PLUGIN_ATTEST_PINS_MALFORMED",
        "fix the builder pin file: one 64 lowercase hex public key per line, # comments, at most 256 keys" },
    [PLUGIN_ATTEST_THRESHOLD_INVALID] = { "PLUGIN_ATTEST_THRESHOLD_INVALID",
        "pass a threshold of at least 1" },
    [PLUGIN_ATTEST_THRESHOLD_EXCEEDS_PINS] = { "PLUGIN_ATTEST_THRESHOLD_EXCEEDS_PINS",
        "pin more independent builder keys or lower the threshold; the threshold may not exceed the pinned builders" },
    [PLUGIN_ATTEST_TOO_MANY_FILES] = { "PLUGIN_ATTEST_TOO_MANY_FILES",
        "keep at most 256 attestation files per directory" },
    [PLUGIN_ATTEST_SUBJECT_MISMATCH] = { "PLUGIN_ATTEST_SUBJECT_MISMATCH",
        "keep only attestations for this plugin name and version in the directory" },
    [PLUGIN_ATTEST_BUILDER_UNPINNED] = { "PLUGIN_ATTEST_BUILDER_UNPINNED",
        "pin the builder key only after you verified who runs it, or remove the attestation" },
    [PLUGIN_ATTEST_DUPLICATE_BUILDER] = { "PLUGIN_ATTEST_DUPLICATE_BUILDER",
        "keep one attestation per builder key; one builder counts once" },
    [PLUGIN_ATTEST_HASH_MISMATCH] = { "PLUGIN_ATTEST_HASH_MISMATCH",
        "the builder got different bytes than the manifest names: do not install, report the divergence" },
    [PLUGIN_ATTEST_SOURCE_ROOT_MISMATCH] = { "PLUGIN_ATTEST_SOURCE_ROOT_MISMATCH",
        "builders attested different source roots: rebuild from one agreed source package root" },
    [PLUGIN_ATTEST_BELOW_THRESHOLD] = { "PLUGIN_ATTEST_BELOW_THRESHOLD",
        "collect attestations from more distinct pinned builders" },
};

const char *plugin_attest_status_code(enum plugin_attest_status status)
{
    size_t n = sizeof(pa_text) / sizeof(pa_text[0]);
    return (size_t)status < n ? pa_text[status].code : "PLUGIN_ATTEST_UNKNOWN";
}

const char *plugin_attest_status_next_action(enum plugin_attest_status status)
{
    size_t n = sizeof(pa_text) / sizeof(pa_text[0]);
    return (size_t)status < n ? pa_text[status].next_action : "";
}

static bool pa_toolchain_valid(const char *s, size_t len)
{
    if (len == 0 || len > PLUGIN_ATTEST_TOOLCHAIN_MAX)
        return false;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                  c == ':' || c == '+' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

static bool pa_value_valid(enum pa_kind kind, const char *s, size_t len)
{
    switch (kind) {
    case PA_NAME: {
        char tmp[PLUGIN_NAME_MAX + 1];
        if (len == 0 || len > PLUGIN_NAME_MAX)
            return false;
        memcpy(tmp, s, len);
        tmp[len] = '\0';
        return plugin_name_valid(tmp);
    }
    case PA_VERSION: {
        char tmp[PLUGIN_VERSION_MAX + 1];
        if (len == 0 || len > PLUGIN_VERSION_MAX)
            return false;
        memcpy(tmp, s, len);
        tmp[len] = '\0';
        return plugin_version_valid(tmp);
    }
    case PA_TOOLCHAIN:
        return pa_toolchain_valid(s, len);
    case PA_KEY:
    case PA_SIG:
    case PA_IMAGE:
        break;
    }
    return false; /* hex kinds are length-exact and checked by the caller */
}

/* Hex kinds are exact length: key 64, signature 128, image 128. */
static bool pa_field_ok(size_t index, const char *s, size_t len)
{
    enum pa_kind kind = pa_fields[index].kind;
    if (kind == PA_KEY || kind == PA_SIG || kind == PA_IMAGE) {
        if (len != pa_fields[index].cap)
            return false;
        char tmp[PLUGIN_HEX_SHA3_512 + 1];
        memcpy(tmp, s, len);
        tmp[len] = '\0';
        return plugin_hex_valid(tmp, len);
    }
    return pa_value_valid(kind, s, len);
}

static const char *pa_field_ptr(const struct plugin_attest_record *rec, size_t index)
{
    return (const char *)rec + pa_fields[index].offset;
}

/* Writes the first `count` fields; returns the length or 0. */
static size_t pa_write(const struct plugin_attest_record *rec, size_t count,
                       char *out, size_t cap)
{
    size_t pos = 0;
    for (size_t i = 0; i < count; i++) {
        const char *v = pa_field_ptr(rec, i);
        size_t vl = strnlen(v, pa_fields[i].cap + 1u);
        size_t ll = strlen(pa_fields[i].lead);
        if (!pa_field_ok(i, v, vl) || pos + ll + vl + 1u >= cap)
            return 0;
        memcpy(out + pos, pa_fields[i].lead, ll);
        memcpy(out + pos + ll, v, vl);
        pos += ll + vl;
    }
    return pos;
}

size_t plugin_attest_encode(const struct plugin_attest_record *rec, char *out,
                            size_t cap)
{
    if (!rec || !out)
        return 0;
    size_t n = pa_write(rec, PA_FIELD_COUNT, out, cap);
    if (n == 0 || n + sizeof(PA_TAIL) > cap)
        return 0;
    memcpy(out + n, PA_TAIL, sizeof(PA_TAIL));
    return n + sizeof(PA_TAIL) - 1u;
}

static bool pa_lead(const char *p, const char *end, const char *lead)
{
    size_t n = strlen(lead);
    return (size_t)(end - p) >= n && memcmp(p, lead, n) == 0;
}

/* Reads one value that must close with a double quote within its bound. */
static const char *pa_take(const char *p, const char *end, size_t index,
                           struct plugin_attest_record *out)
{
    size_t window = (size_t)(end - p);
    size_t cap = pa_fields[index].cap;
    const char *q = memchr(p, '"', window < cap + 1u ? window : cap + 1u);
    if (!q || !pa_field_ok(index, p, (size_t)(q - p)))
        return NULL;
    memcpy((char *)out + pa_fields[index].offset, p, (size_t)(q - p));
    return q;
}

enum plugin_attest_status plugin_attest_parse(const char *bytes, size_t len,
                                              struct plugin_attest_record *out)
{
    char again[PLUGIN_ATTEST_RECORD_MAX];
    struct plugin_attest_record rec;
    if (!bytes || !out || len == 0 || len >= PLUGIN_ATTEST_RECORD_MAX)
        return PLUGIN_ATTEST_MALFORMED;
    memset(&rec, 0, sizeof(rec));
    const char *p = bytes, *end = bytes + len;
    for (size_t i = 0; i < PA_FIELD_COUNT; i++) {
        if (!pa_lead(p, end, pa_fields[i].lead))
            return PLUGIN_ATTEST_MALFORMED;
        p += strlen(pa_fields[i].lead);
        p = pa_take(p, end, i, &rec);
        if (!p)
            return PLUGIN_ATTEST_MALFORMED;
    }
    if (!pa_lead(p, end, PA_TAIL) || (size_t)(end - p) != sizeof(PA_TAIL) - 1u)
        return PLUGIN_ATTEST_MALFORMED;
    /* The grammar above is exact; re-encoding is the belt to its braces. */
    size_t n = plugin_attest_encode(&rec, again, sizeof(again));
    if (n != len || memcmp(again, bytes, len) != 0)
        return PLUGIN_ATTEST_MALFORMED;
    *out = rec;
    return PLUGIN_ATTEST_OK;
}

static void pa_digest(const char *prefix, size_t len, uint8_t digest[PLUGIN_DIGEST_BYTES])
{
    static const unsigned char domain[] = PA_SCHEMA; /* sizeof includes the NUL */
    plugin_domain_digest(domain, sizeof(domain), prefix, len, digest);
}

enum plugin_attest_status plugin_attest_check_signature(
    const struct plugin_attest_record *rec)
{
    char prefix[PLUGIN_ATTEST_RECORD_MAX];
    uint8_t pk[32], sig[64], digest[PLUGIN_DIGEST_BYTES];
    if (!rec)
        return PLUGIN_ATTEST_ARGUMENT;
    size_t n = pa_write(rec, PA_SIGNED_FIELDS, prefix, sizeof(prefix));
    if (n == 0 || !zcl_hex_decode_lower(rec->builder_key, pk, sizeof(pk)) ||
        !zcl_hex_decode_lower(rec->signature, sig, sizeof(sig)))
        return PLUGIN_ATTEST_MALFORMED;
    pa_digest(prefix, n, digest);
    return ed25519_verify(sig, digest, sizeof(digest), pk) ? PLUGIN_ATTEST_OK
                                                            : PLUGIN_ATTEST_SIG_BAD;
}

static bool pa_request_valid(const struct plugin_attest_request *r)
{
    return r && r->image_path && r->key_path && r->name && r->version &&
           r->source_root && r->toolchain && plugin_name_valid(r->name) &&
           plugin_version_valid(r->version) &&
           pa_toolchain_valid(r->toolchain, strlen(r->toolchain)) &&
           strlen(r->source_root) == PLUGIN_ATTEST_HEX_KEY &&
           plugin_hex_valid(r->source_root, PLUGIN_ATTEST_HEX_KEY);
}

static void pa_fill(struct plugin_attest_record *rec,
                    const struct plugin_attest_request *r, const char *image,
                    const uint8_t seed[PLUGIN_KEY_FILE_BYTES])
{
    uint8_t pk[32], sig[64], digest[PLUGIN_DIGEST_BYTES];
    char prefix[PLUGIN_ATTEST_RECORD_MAX];
    memset(rec, 0, sizeof(*rec));
    snprintf(rec->name, sizeof(rec->name), "%s", r->name);
    snprintf(rec->version, sizeof(rec->version), "%s", r->version);
    snprintf(rec->source_root, sizeof(rec->source_root), "%s", r->source_root);
    snprintf(rec->toolchain, sizeof(rec->toolchain), "%s", r->toolchain);
    snprintf(rec->image, sizeof(rec->image), "%s", image);
    plugin_key_public(seed, pk);
    zcl_hex_encode(pk, sizeof(pk), rec->builder_key);
    size_t n = pa_write(rec, PA_SIGNED_FIELDS, prefix, sizeof(prefix));
    pa_digest(prefix, n, digest);
    ed25519_sign(sig, digest, sizeof(digest), seed, pk);
    zcl_hex_encode(sig, sizeof(sig), rec->signature);
}

static enum plugin_attest_status pa_store(const struct plugin_attest_request *r,
                                          struct plugin_attest_result *out)
{
    char bytes[PLUGIN_ATTEST_RECORD_MAX], leaf[PLUGIN_NAME_MAX + 40];
    size_t n = plugin_attest_encode(&out->record, bytes, sizeof(bytes));
    int ln = snprintf(leaf, sizeof(leaf), "%s-%.16s" PLUGIN_ATTEST_SUFFIX, r->name,
                      out->record.builder_key);
    if (n == 0 || ln <= 0 || (size_t)ln >= sizeof(leaf) ||
        !plugin_join(out->path, sizeof(out->path), r->dir ? r->dir : ".", leaf,
                     NULL, NULL))
        return PLUGIN_ATTEST_ARGUMENT;
    return plugin_write_atomic(out->path, bytes, n) ? PLUGIN_ATTEST_OK : PLUGIN_ATTEST_IO;
}

enum plugin_attest_status plugin_attest_make(
    const struct plugin_attest_request *request,
    struct plugin_attest_result *result)
{
    uint8_t seed[PLUGIN_KEY_FILE_BYTES];
    char image[PLUGIN_HEX_SHA3_512 + 1];
    if (!result)
        return PLUGIN_ATTEST_ARGUMENT;
    memset(result, 0, sizeof(*result));
    if (!pa_request_valid(request))
        return PLUGIN_ATTEST_ARGUMENT;
    result->cause = plugin_key_load(request->key_path, seed);
    if (result->cause != PLUGIN_OK)
        return PLUGIN_ATTEST_UPSTREAM;
    result->cause = plugin_hash_file(request->image_path, image);
    if (result->cause != PLUGIN_OK) {
        memory_cleanse(seed, sizeof(seed));
        return PLUGIN_ATTEST_UPSTREAM;
    }
    pa_fill(&result->record, request, image, seed);
    memory_cleanse(seed, sizeof(seed));
    return pa_store(request, result);
}
