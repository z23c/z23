/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the `zcode desc` tree — signed onion-service
 * descriptors (docs/spec/sovereign-identity-layer.md, "A1"). A
 * descriptor is a zid_doc whose body carries the service's v3 hostname,
 * its introduction points, and the moment its validity opens (body tag
 * "ZIDD", lib/zid/include/zid/zdesc.h). Publishing stores the canonical
 * doc wire as a content-addressed blob (lib/vcs/include/vcs/blob_store.h)
 * so it moves over the already-frozen package swarm with no new message.
 *
 * ADDRESSING: a descriptor is filed under the BLINDED record key for a
 * time period — SHA3-256("ZIDB" ‖ master_pubkey ‖ period_le64), a whole
 * UTC day. Only someone who already knows the master key can compute
 * the address, which is what kills directory harvesting. `resolve`
 * derives the same key from the caller's clock and falls back to the
 * previous period so a publish either side of midnight is still
 * findable.
 *
 * WHAT VERIFICATION MEANS HERE, precisely: every reply is verified
 * against a CALLER-SUPPLIED master pubkey. Nothing in this file
 * consults the chain, and no reply claims a descriptor is
 * chain-anchored — each carries chain_anchored:false and
 * verified_against:"supplied_key" so the claim is machine-readable
 * rather than only prose. The single seam that will close this lives in
 * lib/vcs/src/zdesc_swarm.c (CHAIN-BINDING SEAM).
 *
 * Secret hygiene (publish): the seed file must be exactly 64 hex chars
 * with 0600/0400 perms; the seed is memory_cleanse'd after use and is
 * NEVER logged or echoed. */

#include "command/native_command.h"

#include "base/log_macros.h"
#include "crypto/ed25519.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "platform/directory_transaction.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/rng.h"
#include "platform/time_compat.h"
#include "support/cleanse.h"
#include "vcs/package_store.h"
#include "vcs/zdesc_swarm.h"
#include "zid/zdesc.h"
#include "zid/zid.h"

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#define ZDC_DEFAULT_VALIDITY_SECONDS (3 * 86400)

/* ── input helpers (native_zcode_release_command.c shape) ─────────── */

static const char *zdc_input_str(const struct json_value *input,
                                 const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

/* Accept a number either typed (JSON_INT) or as a decimal string.
 *
 * The registry's input-key type rule (lib/kernel/src/command_registry.c)
 * only admits JSON_INT for keys it names explicitly and demands a
 * string for everything else, so `--seq=5` inside --input='{...}' is
 * refused INVALID_INPUT for any key without such a rule. Taking both
 * forms here means these leaves work today with `"seq":"5"` and keep
 * working unchanged if typed rules are added later. A string that is
 * not a clean whole number falls back to `dflt` rather than silently
 * reading as 0. */
static int64_t zdc_input_int(const struct json_value *input, const char *key,
                             int64_t dflt)
{
    const struct json_value *v = json_get(input, key);
    if (!v)
        return dflt;
    if (v->type == JSON_INT)
        return json_get_int(v);
    if (v->type == JSON_STR) {
        const char *s = json_get_str(v);
        if (!s || !s[0])
            return dflt;
        char *end = NULL;
        long long parsed = strtoll(s, &end, 10);
        if (end && *end == '\0')
            return (int64_t)parsed;
    }
    return dflt;
}

static const char *zdc_datadir(const struct zcl_command_request *request)
{
    const char *dd = zdc_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

static void zdc_fail(struct zcl_command_reply *reply, const char *code,
                     const char *phase, const char *message,
                     const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, false,
                           false, message, evidence);
}

/* ── seed loading (0600/0400, cleansed, never logged) ─────────────── */

static bool zdc_read_stable(const char *path, void *out, size_t capacity,
                            size_t *length)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (length) *length = 0;
    if (!path || !out || !length || !capacity ||
        !platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before) ||
        before.size == 0 || before.size > capacity) {
        platform_positioned_file_close(&file);
        return false;
    }
    bool ok = platform_positioned_file_read(
            &file, out, (size_t)before.size, 0) == (int64_t)before.size &&
        platform_positioned_file_snapshot(&file, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (ok) *length = (size_t)before.size;
    return ok;
}

static bool zdc_read_seed(const char *path, uint8_t seed_out[32], char *err,
                          size_t err_size)
{
    struct platform_positioned_file seed;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&seed);
    bool private_seed = platform_positioned_file_open(&seed, path) &&
        platform_positioned_file_is_current_user_only(&seed) &&
        platform_positioned_file_snapshot(&seed, &before) &&
        (before.size == 64 || before.size == 65);
    if (!private_seed) {
        platform_positioned_file_close(&seed);
        snprintf(err, err_size,
                 "seed file must be private to the current user%s",
                 path ? "" : " and have a valid path");
        return false;
    }
    uint8_t raw[65];
    size_t n = (size_t)before.size;
    bool read_ok = platform_positioned_file_read(&seed, raw, n, 0) ==
                       (int64_t)n &&
        platform_positioned_file_snapshot(&seed, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&seed);
    if (!read_ok || n < 64 || (n != 64 && !(n == 65 && raw[64] == '\n'))) {
        memory_cleanse(raw, sizeof(raw));
        snprintf(err, err_size,
                 "seed file must be exactly 64 hex chars (read %zu bytes)", n);
        return false;
    }
    char hex[65];
    memcpy(hex, raw, 64);
    hex[64] = '\0';
    memory_cleanse(raw, sizeof(raw));
    bool ok = IsHex(hex) && ParseHex(hex, seed_out, 32) == 32;
    memory_cleanse(hex, sizeof(hex));
    if (!ok)
        snprintf(err, err_size, "seed file is not 64 hex chars");
    return ok;
}

/* ── the local record file: <datadir>/zcode/descriptors/<key>.zid ──
 *
 * A file named by the BLINDED record key, holding the doc hex. It is a
 * local witness for the record_key -> descriptor mapping, nothing more:
 * distributing that mapping to strangers is not built in this slice
 * (see THE OPEN EDGE in vcs/zdesc_swarm.h). */

static bool zdc_record_dir(const char *datadir, char *out, size_t out_size,
                           char *err, size_t err_size)
{
    char dir[1024];
    int n = snprintf(dir, sizeof(dir), "%s/zcode", datadir);
    if (n <= 0 || (size_t)n >= sizeof(dir)) {
        snprintf(err, err_size, "path too long under datadir");
        return false;
    }
#if defined(_WIN32)
    if (!platform_private_directory_ensure(dir)) {
        snprintf(err, err_size, "private directory refused: %s", dir);
#else
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        snprintf(err, err_size, "mkdir %s: %s", dir, strerror(errno));
#endif
        return false;
    }
    n = snprintf(out, out_size, "%s/zcode/descriptors", datadir);
    if (n <= 0 || (size_t)n >= out_size) {
        snprintf(err, err_size, "path too long under datadir");
        return false;
    }
#if defined(_WIN32)
    if (!platform_private_directory_ensure(out)) {
        snprintf(err, err_size, "private directory refused: %s", out);
#else
    if (mkdir(out, 0700) != 0 && errno != EEXIST) {
        snprintf(err, err_size, "mkdir %s: %s", out, strerror(errno));
#endif
        return false;
    }
    return true;
}

static bool zdc_write_record(const char *datadir, const char *key_hex,
                             const char *doc_hex, char *path_out,
                             size_t path_size, char *err, size_t err_size)
{
    char dir[1024];
    if (!zdc_record_dir(datadir, dir, sizeof(dir), err, err_size))
        return false;
    int n = snprintf(path_out, path_size, "%s/%s.zid", dir, key_hex);
    if (n <= 0 || (size_t)n >= path_size) {
        snprintf(err, err_size, "path too long under datadir");
        return false;
    }
#if defined(_WIN32)
    char leaf[80], staged_leaf[96];
    uint8_t nonce[12];
    char nonce_hex[25];
    n = snprintf(leaf, sizeof(leaf), "%s.zid", key_hex);
    bool named = rng_fill(nonce, sizeof(nonce));
    if (named) HexStr(nonce, sizeof(nonce), false, nonce_hex,
                      sizeof(nonce_hex));
    int sn = named ? snprintf(staged_leaf, sizeof(staged_leaf),
                              ".%s.%s.tmp", key_hex, nonce_hex) : -1;
    struct platform_directory_transaction directory;
    struct platform_directory_child file;
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&file);
    enum platform_directory_result opened = n > 0 && (size_t)n < sizeof(leaf) &&
        sn > 0 && (size_t)sn < sizeof(staged_leaf) &&
        platform_directory_transaction_open(&directory, dir)
        ? (platform_directory_child_create(&directory, staged_leaf, &file)
              ? PLATFORM_DIRECTORY_OK : PLATFORM_DIRECTORY_REFUSED)
        : PLATFORM_DIRECTORY_REFUSED;
    size_t len = strlen(doc_hex);
    bool ok = opened == PLATFORM_DIRECTORY_OK &&
        platform_directory_child_truncate(&file, 0) &&
        platform_directory_child_write_exact(&file, doc_hex, len, 0) &&
        platform_directory_child_write_exact(&file, "\n", 1, len) &&
        platform_directory_child_flush(&file) &&
        platform_directory_child_replace(&directory, &file, leaf, false) &&
        platform_directory_transaction_flush(&directory);
    platform_directory_child_close(&file);
    if (opened == PLATFORM_DIRECTORY_OK && !ok)
        (void)platform_directory_child_unlink(
            &directory, staged_leaf, true);
    platform_directory_transaction_close(&directory);
    if (!ok) snprintf(err, err_size, "private record write refused: %s", path_out);
    return ok;
#else
    int fd = open(path_out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        snprintf(err, err_size, "open %s: %s", path_out, strerror(errno));
        return false;
    }
    size_t len = strlen(doc_hex);
    ssize_t w = write(fd, doc_hex, len);
    ssize_t w2 = (w == (ssize_t)len) ? write(fd, "\n", 1) : -1;
    close(fd);
    if (w != (ssize_t)len || w2 != 1) {
        snprintf(err, err_size, "write %s: %s", path_out, strerror(errno));
        return false;
    }
    return true;
#endif
}

/* Read the doc hex filed under one record key. Returns false when the
 * record simply is not there (the common, non-error case). */
static bool zdc_read_record(const char *datadir, const char *key_hex,
                            char *hex_out, size_t hex_size, char *path_out,
                            size_t path_size)
{
    int n = snprintf(path_out, path_size, "%s/zcode/descriptors/%s.zid",
                     datadir, key_hex);
    if (n <= 0 || (size_t)n >= path_size)
        return false;
    size_t r = 0;
    if (!zdc_read_stable(path_out, hex_out, hex_size - 1, &r))
        return false;
    while (r > 0 && (hex_out[r - 1] == '\n' || hex_out[r - 1] == '\r' ||
                     hex_out[r - 1] == ' '))
        r--;
    hex_out[r] = '\0';
    return r > 0;
}

static void zdc_hex32(const uint8_t in[32], char out[65])
{
    HexStr(in, 32, false, out, 65);
}

/* The highest seq already ON DISK for this identity.
 *
 * Each CLI invocation is a fresh process, so the in-memory directory's
 * monotonic-seq rule cannot see the previous publish — without this the
 * surface would let a replayed lower seq overwrite a newer descriptor,
 * which is exactly what the seq rule exists to prevent. The record key
 * rotates each period, so the predecessor lives in a different file:
 * both are consulted. Returns false when no record exists yet.
 *
 * A file that does not decode, or that is signed by another identity,
 * is ignored rather than trusted — it cannot be OUR held descriptor. */
static bool zdc_held_seq(const char *datadir, const uint8_t pk[32],
                         uint64_t period, uint64_t *out_seq)
{
    bool found = false;
    uint64_t best = 0;
    uint64_t periods[2] = { period, zdesc_period_prev(period) };
    size_t n_periods = (period == periods[1]) ? 1u : 2u;

    for (size_t i = 0; i < n_periods; i++) {
        uint8_t key[32];
        char key_hex[65], path[1200];
        static char hex[ZID_DOC_MAX * 2 + 2];
        zdesc_record_key(key, pk, periods[i]);
        zdc_hex32(key, key_hex);
        if (!zdc_read_record(datadir, key_hex, hex, sizeof(hex), path,
                             sizeof(path)))
            continue;
        size_t hex_len = strlen(hex);
        if ((hex_len & 1u) != 0 || !IsHex(hex))
            continue;
        uint8_t wire[ZID_DOC_MAX];
        size_t wire_len = (size_t)ParseHex(hex, wire, sizeof(wire));
        struct zid_doc doc;
        if (wire_len == 0 || !zid_doc_decode(&doc, wire, wire_len))
            continue;
        if (memcmp(doc.master_pubkey, pk, 32) != 0)
            continue;
        if (!found || doc.seq > best)
            best = doc.seq;
        found = true;
    }
    if (found && out_seq)
        *out_seq = best;
    return found;
}

/* ── shared reply shaping ──────────────────────────────────────────── */

/* Every descriptor reply carries the same two fields, so no consumer
 * has to read prose to learn what the verification actually proved. */
static void zdc_push_verification_status(struct zcl_command_reply *reply)
{
    json_push_kv_bool(&reply->data, "chain_anchored", false);
    json_push_kv_str(&reply->data, "verified_against", "supplied_key");
    json_push_kv_str(&reply->data, "verification_note",
                     "the signature was checked against the master key you "
                     "supplied — this does NOT prove the key is anchored "
                     "on-chain");
}

static void zdc_push_descriptor(struct zcl_command_reply *reply,
                                const struct zid_doc *doc,
                                const struct zdesc *desc)
{
    char pk_hex[65];
    zdc_hex32(doc->master_pubkey, pk_hex);
    json_push_kv_str(&reply->data, "master_pubkey", pk_hex);
    json_push_kv_str(&reply->data, "onion", desc->onion);
    json_push_kv_int(&reply->data, "seq", (int64_t)doc->seq);
    json_push_kv_int(&reply->data, "not_before", (int64_t)desc->not_before);
    json_push_kv_int(&reply->data, "expiry", (int64_t)doc->expiry);
    json_push_kv_int(&reply->data, "intro_count", desc->intro_count);

    struct json_value intros;
    json_init(&intros);
    json_set_array(&intros);
    for (uint8_t i = 0; i < desc->intro_count; i++) {
        struct json_value one;
        json_init(&one);
        json_set_object(&one);
        json_push_kv_str(&one, "onion", desc->intro[i].onion);
        char key_hex[65];
        zdc_hex32(desc->intro[i].auth_key, key_hex);
        json_push_kv_str(&one, "auth_key", key_hex);
        json_push_back(&intros, &one);
        json_free(&one);
    }
    json_push_kv(&reply->data, "intros", &intros);
    json_free(&intros);
}

/* Decode 'doc' hex (or read it from 'file') into wire bytes. Fills the
 * reply's error body and returns 0 on every failure path. */
static size_t zdc_load_doc_wire(const struct json_value *in,
                                struct zcl_command_reply *reply,
                                const char *cmd, uint8_t *wire,
                                size_t wire_cap)
{
    const char *doc_hex = zdc_input_str(in, "doc");
    const char *file = zdc_input_str(in, "file");
    if ((!doc_hex || !doc_hex[0]) && (!file || !file[0])) {
        zdc_fail(reply, "MISSING_DOC", "normalize",
                 "give --doc=<hex> (from `zcode desc publish`) or "
                 "--file=<path to a saved .zid>", cmd);
        return 0;
    }
    static char file_hex[ZID_DOC_MAX * 2 + 2];
    if (!doc_hex || !doc_hex[0]) {
        size_t n = 0;
        if (!zdc_read_stable(file, file_hex, sizeof(file_hex) - 1, &n)) {
            zdc_fail(reply, "DOC_UNREADABLE", "normalize",
                     "cannot stably read bounded doc file", file);
            return 0;
        }
        while (n > 0 && (file_hex[n - 1] == '\n' || file_hex[n - 1] == '\r' ||
                         file_hex[n - 1] == ' '))
            n--;
        file_hex[n] = '\0';
        doc_hex = file_hex;
    }
    size_t hex_len = strlen(doc_hex);
    if (hex_len == 0 || (hex_len & 1u) != 0 || hex_len > wire_cap * 2 ||
        !IsHex(doc_hex)) {
        zdc_fail(reply, "BAD_DOC_HEX", "normalize",
                 "doc must be even-length hex, at most 2*ZID_DOC_MAX chars "
                 "— pass the exact doc_hex from `zcode desc publish`", cmd);
        return 0;
    }
    size_t n = (size_t)ParseHex(doc_hex, wire, wire_cap);
    if (n == 0) {
        zdc_fail(reply, "BAD_DOC_HEX", "normalize", "doc hex did not decode",
                 cmd);
        return 0;
    }
    return n;
}

/* Read the required 64-hex master pubkey. */
static bool zdc_load_pubkey(const struct json_value *in,
                            struct zcl_command_reply *reply, const char *cmd,
                            uint8_t out[32])
{
    const char *hex = zdc_input_str(in, "pubkey");
    if (!hex || strlen(hex) != 64 || !IsHex(hex) ||
        ParseHex(hex, out, 32) != 32) {
        zdc_fail(reply, "BAD_PUBKEY", "normalize",
                 "pubkey must be the 64-hex ed25519 master public key of the "
                 "identity you expect signed this descriptor — verification "
                 "is against THIS key, not against the chain", cmd);
        return false;
    }
    return true;
}

/* Map a zdesc_result onto the reply's error body. Every code names what
 * went wrong; none of them is silent. */
static void zdc_fail_result(struct zcl_command_reply *reply,
                            enum zdesc_result r, const char *cmd)
{
    switch (r) {
    case ZDESC_ERR_ABSENT:
        zdc_fail(reply, "DESCRIPTOR_ABSENT", "execute",
                 "no descriptor is filed under this identity's record key "
                 "for the current period or the one before — the publisher "
                 "must republish each period", cmd);
        return;
    case ZDESC_ERR_KEY_MISMATCH:
        zdc_fail(reply, "KEY_MISMATCH", "execute",
                 "the descriptor is signed by a different identity than the "
                 "pubkey you supplied", cmd);
        return;
    case ZDESC_ERR_VERIFY:
        zdc_fail(reply, "VERIFY_FAILED", "execute",
                 "signature or validity window failed — the descriptor is "
                 "tampered, corrupted, or expired (ask the publisher to "
                 "re-sign with a higher seq)", cmd);
        return;
    case ZDESC_ERR_BODY:
        zdc_fail(reply, "NOT_A_DESCRIPTOR_BODY", "execute",
                 "the signature held but the body is not a ZIDD descriptor, "
                 "or its validity window has not opened yet", cmd);
        return;
    case ZDESC_ERR_DECODE:
        zdc_fail(reply, "DOC_DECODE_FAILED", "execute",
                 "not a well-formed zid doc — check the hex was not "
                 "truncated", cmd);
        return;
    case ZDESC_ERR_STALE:
        zdc_fail(reply, "STALE_SEQ", "execute",
                 "seq does not supersede the descriptor already held for "
                 "this identity — rotation needs a strictly higher seq", cmd);
        return;
    case ZDESC_ERR_ONION:
        zdc_fail(reply, "BAD_ONION", "normalize",
                 "hostname is not a v3 onion (56 base32 a-z2-7 chars + "
                 "\".onion\", 62 total)", cmd);
        return;
    case ZDESC_ERR_SIGN:
        zdc_fail(reply, "SIGN_FAILED", "execute",
                 "signing refused — expiry must be strictly after "
                 "not_before, and every introduction point must be a v3 "
                 "onion", cmd);
        return;
    case ZDESC_ERR_BLOB:
        zdc_fail(reply, "BLOB_FAILED", "execute",
                 "the content-addressed store refused the descriptor blob "
                 "(quota, permissions, or I/O)", cmd);
        return;
    case ZDESC_ERR_FULL:
        zdc_fail(reply, "DIRECTORY_FULL", "execute",
                 "the in-process descriptor directory is full", cmd);
        return;
    default:
        zdc_fail(reply, "DESCRIPTOR_FAILED", "execute",
                 zdesc_result_string(r), cmd);
        return;
    }
}

/* ── zcode.desc.publish ────────────────────────────────────────────── */

void zcl_native_handle_zdesc_publish(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const struct json_value *in = request->input;
    const char *cmd = "zcode.desc.publish";

    const char *onion = zdc_input_str(in, "onion");
    if (!onion || !zdesc_onion_valid(onion)) {
        zdc_fail(reply, "BAD_ONION", "normalize",
                 "onion must be the service's v3 hostname: 56 base32 "
                 "(a-z2-7) chars + \".onion\", 62 total", cmd);
        return;
    }
    const char *seed_file = zdc_input_str(in, "seed_file");
    if (!seed_file || !seed_file[0]) {
        zdc_fail(reply, "MISSING_SEED_FILE", "normalize",
                 "missing seed_file — path to a 0600 file holding the "
                 "64-hex master seed", cmd);
        return;
    }

    struct zdesc desc;
    memset(&desc, 0, sizeof(desc));
    snprintf(desc.onion, sizeof(desc.onion), "%s", onion);

    int64_t now = zdc_input_int(in, "now", 0);
    if (now <= 0)
        now = platform_time_wall_unix();
    int64_t not_before = zdc_input_int(in, "not_before", now);
    if (not_before < 0) {
        zdc_fail(reply, "BAD_NOT_BEFORE", "normalize",
                 "not_before must be a unix timestamp >= 0", cmd);
        return;
    }
    desc.not_before = (uint64_t)not_before;

    int64_t seq = zdc_input_int(in, "seq", 1);
    if (seq < 0) {
        zdc_fail(reply, "BAD_SEQ", "normalize",
                 "seq must be >= 0 and monotonic per identity — rotation "
                 "means a strictly higher seq", cmd);
        return;
    }
    int64_t expiry = zdc_input_int(in, "expiry", 0);
    if (expiry == 0)
        expiry = not_before + ZDC_DEFAULT_VALIDITY_SECONDS;
    if (expiry <= not_before) {
        zdc_fail(reply, "BAD_WINDOW", "normalize",
                 "expiry must be strictly after not_before — otherwise the "
                 "validity window never opens", cmd);
        return;
    }

    /* Introduction points, in either of two equivalent forms:
     *   - a JSON array of {"onion","auth_key"} objects, or
     *   - the flat string "<onion>:<64hex>,<onion>:<64hex>,..."
     * The registry's input-key type rule admits a bare string for any
     * key it does not name, so the flat form is what actually works
     * from the command line today; the array form is accepted so the
     * leaf keeps working unchanged if a typed rule is added later. */
    const struct json_value *intros = json_get(in, "intros");
    if (intros && intros->type == JSON_STR) {
        const char *s = json_get_str(intros);
        size_t count = 0;
        while (s && *s) {
            if (count == ZDESC_INTRO_MAX) {
                zdc_fail(reply, "TOO_MANY_INTROS", "normalize",
                         "at most 8 introduction points fit one descriptor",
                         cmd);
                return;
            }
            const char *colon = strchr(s, ':');
            const char *comma = strchr(s, ',');
            size_t item_len = comma ? (size_t)(comma - s) : strlen(s);
            if (!colon || (comma && colon > comma) ||
                (size_t)(colon - s) != (size_t)ZDESC_ONION_LEN ||
                item_len != (size_t)ZDESC_ONION_LEN + 1u + 64u) {
                zdc_fail(reply, "BAD_INTROS", "normalize",
                         "each introduction point must be "
                         "\"<62-char v3 onion>:<64hex auth_key>\", "
                         "comma-separated", cmd);
                return;
            }
            char host[ZDESC_ONION_LEN + 1];
            memcpy(host, s, ZDESC_ONION_LEN);
            host[ZDESC_ONION_LEN] = '\0';
            char keyhex[65];
            memcpy(keyhex, colon + 1, 64);
            keyhex[64] = '\0';
            if (!zdesc_onion_valid(host)) {
                zdc_fail(reply, "BAD_INTRO_ONION", "normalize",
                         "every introduction point needs a v3 onion hostname",
                         cmd);
                return;
            }
            if (!IsHex(keyhex) ||
                ParseHex(keyhex, desc.intro[count].auth_key, 32) != 32) {
                zdc_fail(reply, "BAD_INTRO_KEY", "normalize",
                         "every introduction point needs a 64-hex auth_key",
                         cmd);
                return;
            }
            memcpy(desc.intro[count].onion, host, sizeof(host));
            count++;
            if (!comma)
                break;
            s = comma + 1;
        }
        desc.intro_count = (uint8_t)count;
    } else if (intros && intros->type == JSON_ARR) {
        size_t n = json_size(intros);
        if (n > ZDESC_INTRO_MAX) {
            zdc_fail(reply, "TOO_MANY_INTROS", "normalize",
                     "at most 8 introduction points fit one descriptor", cmd);
            return;
        }
        for (size_t i = 0; i < n; i++) {
            const struct json_value *one = json_at(intros, i);
            const char *ionion = one ? zdc_input_str(one, "onion") : NULL;
            const char *ikey = one ? zdc_input_str(one, "auth_key") : NULL;
            if (!ionion || !zdesc_onion_valid(ionion)) {
                zdc_fail(reply, "BAD_INTRO_ONION", "normalize",
                         "every introduction point needs a v3 onion "
                         "hostname", cmd);
                return;
            }
            if (!ikey || strlen(ikey) != 64 || !IsHex(ikey) ||
                ParseHex(ikey, desc.intro[i].auth_key, 32) != 32) {
                zdc_fail(reply, "BAD_INTRO_KEY", "normalize",
                         "every introduction point needs a 64-hex auth_key",
                         cmd);
                return;
            }
            snprintf(desc.intro[i].onion, sizeof(desc.intro[i].onion), "%s",
                     ionion);
        }
        desc.intro_count = (uint8_t)n;
    } else if (intros) {
        zdc_fail(reply, "BAD_INTROS", "normalize",
                 "intros must be a JSON array of {\"onion\",\"auth_key\"} or the "
                 "string \"<onion>:<64hex>,...\"",
                 cmd);
        return;
    }

    const char *datadir = zdc_datadir(request);
    if (!datadir) {
        zdc_fail(reply, "NO_DATADIR", "normalize",
                 "no datadir resolved — pass --datadir; the descriptor blob "
                 "and its record file are written under "
                 "<datadir>/zcode/", cmd);
        return;
    }

    uint8_t seed[32];
    char err[512];
    if (!zdc_read_seed(seed_file, seed, err, sizeof(err))) {
        zdc_fail(reply, "BAD_SEED_FILE", "normalize", err, seed_file);
        return;
    }

    /* Replay defence across invocations. Each CLI run is a fresh
     * process, so the library's in-memory seq rule sees nothing; the
     * authority here is the record already on disk. Checked BEFORE the
     * store is touched, so a refused republish writes nothing at all. */
    uint8_t pk[32], sk[32];
    ed25519_keypair(pk, sk, seed);
    memory_cleanse(sk, sizeof(sk));
    uint64_t held = 0;
    if (zdc_held_seq(datadir, pk, zdesc_period_at((uint64_t)now), &held) &&
        (uint64_t)seq <= held) {
        memory_cleanse(seed, sizeof(seed));
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "seq %lld does not supersede the descriptor already filed "
                 "for this identity (seq %llu) — rotation needs a strictly "
                 "higher seq; nothing was written",
                 (long long)seq, (unsigned long long)held);
        zdc_fail(reply, "STALE_SEQ", "execute", msg, cmd);
        return;
    }

    struct vcs_package_store *store =
        vcs_package_store_open(datadir, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    if (!store) {
        memory_cleanse(seed, sizeof(seed));
        zdc_fail(reply, "STORE_UNAVAILABLE", "execute",
                 "cannot open the content-addressed package store under "
                 "<datadir>/zcode", datadir);
        return;
    }

    /* The global directory is what the node's signed onion-peer
     * discovery source reads (config/src/boot_services.c), so an
     * in-node publish feeds discovery immediately. */
    struct zdesc_directory *dir = zdesc_directory_global();
    uint8_t root[32], pubkey[32];
    enum zdesc_result r =
        zdesc_publish_to(store, dir, &desc, (uint64_t)seq, (uint64_t)expiry,
                         seed, (uint64_t)now, root, pubkey);
    memory_cleanse(seed, sizeof(seed));
    vcs_package_store_close(store);
    if (r != ZDESC_OK) {
        zdc_fail_result(reply, r, cmd);
        return;
    }

    const struct zdesc_entry *entry = NULL;
    if (!zdesc_directory_find(dir, pubkey, &entry) || !entry) {
        zdc_fail(reply, "DIRECTORY_LOST", "execute",
                 "the descriptor was stored but its directory entry is "
                 "missing", cmd);
        return;
    }
    struct zid_doc doc = entry->doc;
    uint64_t period = entry->period;
    uint8_t record_key[32];
    memcpy(record_key, entry->record_key, 32);

    uint8_t wire[ZID_DOC_MAX];
    size_t wire_len = zid_doc_encode(wire, sizeof(wire), &doc);
    if (wire_len == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ENCODE_FAILED",
                               "serialize", false, true,
                               "zid_doc_encode failed after a successful "
                               "publish", cmd);
        return;
    }
    char doc_hex[ZID_DOC_MAX * 2 + 1];
    HexStr(wire, wire_len, false, doc_hex, sizeof(doc_hex));

    char key_hex[65], root_hex[65], pk_hex[65];
    zdc_hex32(record_key, key_hex);
    zdc_hex32(root, root_hex);
    zdc_hex32(pubkey, pk_hex);

    char saved_path[1200];
    char save_err[512] = {0};
    bool saved = zdc_write_record(datadir, key_hex, doc_hex, saved_path,
                                  sizeof(saved_path), save_err,
                                  sizeof(save_err));

    json_push_kv_str(&reply->data, "doc_hex", doc_hex);
    json_push_kv_int(&reply->data, "doc_bytes", (int64_t)wire_len);
    json_push_kv_str(&reply->data, "root", root_hex);
    json_push_kv_str(&reply->data, "record_key", key_hex);
    json_push_kv_int(&reply->data, "period", (int64_t)period);
    json_push_kv_int(&reply->data, "period_seconds", ZDESC_PERIOD_SECONDS);
    (void)pk_hex;
    zdc_push_descriptor(reply, &doc, &desc);
    zdc_push_verification_status(reply);
    json_push_kv_bool(&reply->data, "saved", saved);
    if (saved)
        json_push_kv_str(&reply->data, "saved_path", saved_path);
    else
        json_push_kv_str(&reply->data, "save_error", save_err);
    json_push_kv_str(&reply->data, "next",
                     "give verifiers the master_pubkey; they resolve with "
                     "`z23 zcode desc resolve --pubkey=<hex>`. "
                     "Republish each period (the record key rotates daily) "
                     "and use a strictly higher seq each time.");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── zcode.desc.verify ─────────────────────────────────────────────── */

void zcl_native_handle_zdesc_verify(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const struct json_value *in = request->input;
    const char *cmd = "zcode.desc.verify";

    uint8_t pubkey[32];
    if (!zdc_load_pubkey(in, reply, cmd, pubkey))
        return;
    uint8_t wire[ZID_DOC_MAX];
    size_t wire_len = zdc_load_doc_wire(in, reply, cmd, wire, sizeof(wire));
    if (wire_len == 0)
        return;

    int64_t now = zdc_input_int(in, "now", 0);
    if (now <= 0)
        now = platform_time_wall_unix();

    /* A caller-owned directory: verify must never mutate node state. */
    struct zdesc_directory dir;
    zdesc_directory_init(&dir);
    struct zdesc desc;
    enum zdesc_result r = zdesc_accept(&dir, pubkey, wire, wire_len,
                                       (uint64_t)now, &desc);
    if (r != ZDESC_OK) {
        zdc_fail_result(reply, r, cmd);
        return;
    }
    struct zid_doc doc;
    if (!zid_doc_decode(&doc, wire, wire_len)) {
        zdc_fail(reply, "DOC_DECODE_FAILED", "execute",
                 "descriptor verified but would not re-decode", cmd);
        return;
    }

    uint64_t period = zdesc_period_at((uint64_t)now);
    uint8_t record_key[32];
    char key_hex[65];
    zdesc_record_key(record_key, doc.master_pubkey, period);
    zdc_hex32(record_key, key_hex);

    json_push_kv_bool(&reply->data, "valid", true);
    json_push_kv_int(&reply->data, "now", now);
    json_push_kv_str(&reply->data, "record_key", key_hex);
    json_push_kv_int(&reply->data, "period", (int64_t)period);
    zdc_push_descriptor(reply, &doc, &desc);
    zdc_push_verification_status(reply);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── zcode.desc.resolve ────────────────────────────────────────────── */

void zcl_native_handle_zdesc_resolve(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const struct json_value *in = request->input;
    const char *cmd = "zcode.desc.resolve";

    uint8_t pubkey[32];
    if (!zdc_load_pubkey(in, reply, cmd, pubkey))
        return;
    const char *datadir = zdc_datadir(request);
    if (!datadir) {
        zdc_fail(reply, "NO_DATADIR", "normalize",
                 "no datadir resolved — pass --datadir; records are read "
                 "from <datadir>/zcode/descriptors/", cmd);
        return;
    }

    int64_t now = zdc_input_int(in, "now", 0);
    if (now <= 0)
        now = platform_time_wall_unix();

    /* THE BOUNDARY RULE: current period first, then the one before, so
     * a publisher on the other side of midnight is still findable. */
    uint64_t period = zdesc_period_at((uint64_t)now);
    uint64_t used = period;
    uint8_t record_key[32];
    char key_hex[65], path[1200];
    static char doc_hex[ZID_DOC_MAX * 2 + 2];
    zdesc_record_key(record_key, pubkey, period);
    zdc_hex32(record_key, key_hex);
    bool found = zdc_read_record(datadir, key_hex, doc_hex, sizeof(doc_hex),
                                 path, sizeof(path));
    if (!found && period > 0) {
        used = zdesc_period_prev(period);
        zdesc_record_key(record_key, pubkey, used);
        zdc_hex32(record_key, key_hex);
        found = zdc_read_record(datadir, key_hex, doc_hex, sizeof(doc_hex),
                                path, sizeof(path));
    }
    if (!found) {
        zdc_fail_result(reply, ZDESC_ERR_ABSENT, cmd);
        return;
    }

    size_t hex_len = strlen(doc_hex);
    uint8_t wire[ZID_DOC_MAX];
    if (hex_len == 0 || (hex_len & 1u) != 0 || !IsHex(doc_hex)) {
        zdc_fail(reply, "BAD_DOC_HEX", "execute",
                 "the record file does not hold even-length hex", path);
        return;
    }
    size_t wire_len = (size_t)ParseHex(doc_hex, wire, sizeof(wire));
    if (wire_len == 0) {
        zdc_fail(reply, "BAD_DOC_HEX", "execute",
                 "the record file's hex did not decode", path);
        return;
    }

    struct zdesc_directory dir;
    zdesc_directory_init(&dir);
    struct zdesc desc;
    enum zdesc_result r = zdesc_accept(&dir, pubkey, wire, wire_len,
                                       (uint64_t)now, &desc);
    if (r != ZDESC_OK) {
        zdc_fail_result(reply, r, cmd);
        return;
    }
    struct zid_doc doc;
    if (!zid_doc_decode(&doc, wire, wire_len)) {
        zdc_fail(reply, "DOC_DECODE_FAILED", "execute",
                 "descriptor verified but would not re-decode", path);
        return;
    }

    json_push_kv_bool(&reply->data, "valid", true);
    json_push_kv_int(&reply->data, "now", now);
    json_push_kv_str(&reply->data, "record_key", key_hex);
    json_push_kv_int(&reply->data, "period", (int64_t)period);
    json_push_kv_int(&reply->data, "period_used", (int64_t)used);
    json_push_kv_bool(&reply->data, "previous_period_fallback",
                      used != period);
    json_push_kv_str(&reply->data, "source_path", path);
    json_push_kv_str(&reply->data, "doc_hex", doc_hex);
    zdc_push_descriptor(reply, &doc, &desc);
    zdc_push_verification_status(reply);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
