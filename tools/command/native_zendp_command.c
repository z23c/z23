/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the `zcode endpoint` tree — SIGNED ENDPOINT
 * RECORDS (zid/zendp.h body tag "ZIDE", carried as a content-addressed
 * blob by vcs/zendp_swarm.h). A node's address stops being a bare
 * string anyone can assert and becomes a document the node SIGNED with
 * a key the chain vouches for.
 *
 * THE ONE DIFFERENCE FROM `zcode desc`, AND IT IS THE POINT. Descriptor
 * replies carry chain_anchored:false and verified_against:"supplied_key"
 * — the caller names the key and a pass means only "signed by the key
 * you named". Nothing in this file takes a key from the caller on the
 * verify side at all: the doc carries its own master_pubkey, that key
 * is resolved through the on-chain zid_identities projection, and an
 * ACTIVE anchor is REQUIRED. Every reply here carries
 * verified_against:"chain_anchor" — the MODEL — plus the anchor state,
 * the height that anchored it, and chain_anchored, which is the ANSWER
 * for that one reply rather than a property of the surface: publish can
 * legitimately succeed with the anchor transaction still unconfirmed,
 * and it reports chain_anchored:false when it does.
 *
 * ── WHY THERE IS NO AUTOMATIC PUBLISH, AND NO FLAG FOR ONE ──────────
 * A descriptor and an endpoint record are the same shape and both are
 * free to publish, so "free, therefore republish on a timer" looks
 * obvious. Three reasons it is wrong here, in ascending order of
 * seriousness:
 *
 *   1. Publishing is a PRIVACY decision, not a maintenance chore. An
 *      endpoint record is a signed, durable, self-authenticating
 *      statement that binds a chain-anchored identity to a network
 *      location at a moment in time. Anyone who learns the master key
 *      can derive the record address for any period and keep the bytes
 *      forever. An operator running over Tor is specifically avoiding
 *      that correlation. Nothing announces this node without the
 *      operator saying so.
 *
 *   2. Auto-republish would need the MASTER SEED resident. The record
 *      key rotates every period, so a republishing daemon must be able
 *      to sign at any time — meaning the 32-byte identity master seed
 *      lives in the node's address space for the process lifetime, or
 *      is re-read off disk on a timer. This surface instead reads the
 *      seed once, under a 0600/0400 perms check, memory_cleanse()s it
 *      before returning, and never logs it. A timer strictly worsens
 *      key handling to save one command per period.
 *
 *   3. Nothing periodic belongs on the shared supervisor tick runner,
 *      and this would have to be. Signing is cheap but the anchor check
 *      is a node.db read, and a blocking DB read on the tick runner is
 *      how this node has been killed by its own watchdog before. A
 *      correct auto-publisher needs its own supervised thread — real
 *      cost, for a convenience the operator did not ask for.
 *
 * So: no timer, no background thread, no opt-in flag. Publication is
 * operator-invoked, and `publish` says in its own reply that the record
 * must be republished each period.
 *
 * ── WHERE THE DURABLE STATE IS ──────────────────────────────────────
 * These handlers run in the CLI process (tools/command/native_command.c),
 * which exits immediately. zendp_directory_global() in a CLI process is
 * therefore write-only memory, so nothing here relies on it: the durable
 * artifact is the record FILE under <datadir>/zcode/endpoints/<key>.zid,
 * and engine/composition/src/boot_endpoint_records.c re-verifies those files into the
 * node's live directory at start, on the boot thread.
 *
 * DISCARD, NOT FLAG. `accept` writes the record file ONLY after
 * zendp_accept() has returned ZENDP_OK, which requires an ACTIVE
 * on-chain anchor. A record that fails any rung — decode, signature,
 * window, body tag, or the chain — leaves NO file behind and enters no
 * directory. There is no "stored but untrusted" state to leak into a
 * later read.
 *
 * Secret hygiene (publish): the seed file must be exactly 64 hex chars
 * with 0600/0400 perms; the seed is memory_cleanse'd after use and is
 * NEVER logged or echoed. */

#include "platform/socket_compat.h" /* Winsock must precede windows.h users. */
#include "command/native_command.h"

#include "base/log_macros.h"
#include "config/boot_endpoint_records.h"
#include "crypto/ed25519.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "platform/directory_transaction.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/time_compat.h"
#include "support/cleanse.h"
#include "vcs/package_store.h"
#include "vcs/zendp_swarm.h"
#include "zid/zdesc.h"
#include "zid/zendp.h"
#include "zid/zid.h"

#include <dirent.h>
#include <errno.h>
#if !defined(_WIN32)
#include <fcntl.h>
#endif
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <process.h>
#endif
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#define ZEC_DEFAULT_VALIDITY_SECONDS (3 * 86400)

/* The record directory holds at most ZENDP_DIR_MAX live identities, so
 * a scan that reads more files than that cannot install more anyway. */
#define ZEC_SCAN_MAX 256

/* ── input helpers (native_zdesc_command.c shape) ─────────────────── */

static const char *zec_input_str(const struct json_value *input,
                                 const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

/* Accept a number either typed (JSON_INT) or as a decimal string — the
 * registry admits JSON_INT only for keys it names explicitly, so
 * `"seq":"5"` works today and `"seq":5` keeps working if a typed rule
 * is added later. A string that is not a clean whole number falls back
 * to `dflt` rather than silently reading as 0. */
static int64_t zec_input_int(const struct json_value *input, const char *key,
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

static const char *zec_datadir(const struct zcl_command_request *request)
{
    const char *dd = zec_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

static void zec_fail(struct zcl_command_reply *reply, const char *code,
                     const char *phase, const char *message,
                     const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, false,
                           false, message, evidence);
}

/* The ceiling is stated ONCE, in zid/zendp.h. This renders it for the
 * operator rather than restating "30" here, so the sentence can never
 * disagree with the rule that produced the refusal. */
static const char *zec_window_too_long_message(void)
{
    static char msg[384];
    if (msg[0] == '\0')
        snprintf(msg, sizeof(msg),
                 "the signed validity window is longer than this node will "
                 "honour — the maximum is %llu seconds (%llu days) from "
                 "not_before to expiry. Re-publish with a nearer expiry: a "
                 "record keeps advertising its key until that expiry on any "
                 "node that never sees the key revoked, so the window is the "
                 "bound on how long a retired key stays reachable.",
                 (unsigned long long)ZENDP_MAX_WINDOW_SECONDS,
                 (unsigned long long)(ZENDP_MAX_WINDOW_SECONDS / 86400u));
    return msg;
}

#if defined(_WIN32)
static bool zec_snapshot_same(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
    return a->size == b->size && a->volume == b->volume &&
        a->file_low == b->file_low && a->file_high == b->file_high &&
        a->modified_seconds == b->modified_seconds &&
        a->modified_nanoseconds == b->modified_nanoseconds &&
        a->changed_seconds == b->changed_seconds &&
        a->changed_nanoseconds == b->changed_nanoseconds;
}

static bool zec_stable_read(const char *path, void *bytes, size_t capacity,
                            size_t *size_out, bool private_file)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open(&file, path) &&
        (!private_file || platform_positioned_file_is_private(&file)) &&
        platform_positioned_file_snapshot(&file, &before) &&
        before.size <= capacity;
    int64_t got = ok ? platform_positioned_file_read(
                           &file, bytes, (size_t)before.size, 0) : -1;
    ok = ok && got >= 0 && (uint64_t)got == before.size &&
        platform_positioned_file_snapshot(&file, &after) &&
        zec_snapshot_same(&before, &after);
    platform_positioned_file_close(&file);
    if (ok && size_out) *size_out = (size_t)before.size;
    return ok;
}
#endif

/* Every library refusal gets its own operator-facing code and sentence.
 * The four chain outcomes stay four outcomes: "the chain could not be
 * asked" must never read the same as "the chain said no". */
static void zec_fail_result(struct zcl_command_reply *reply,
                            enum zendp_result r, const char *evidence)
{
    const char *code = "ENDPOINT_REFUSED";
    const char *msg = zendp_result_string(r);
    switch (r) {
    case ZENDP_ERR_NULL:
        code = "BAD_ARGUMENT";
        msg = "a required argument was missing";
        break;
    case ZENDP_ERR_SHAPE:
        code = "BAD_ENDPOINT";
        msg = "the record names no reachable endpoint, or carries a field "
              "its flags do not claim";
        break;
    case ZENDP_ERR_ENCODE:
        code = "ENCODE_FAILED";
        msg = "the record would not encode";
        break;
    case ZENDP_ERR_SIGN:
        code = "SIGN_REFUSED";
        msg = "signing refused — the validity window never opens (expiry "
              "must be after not_before) or the seed is unusable";
        break;
    case ZENDP_ERR_WINDOW_TOO_LONG:
        code = "WINDOW_TOO_LONG";
        msg = zec_window_too_long_message();
        break;
    case ZENDP_ERR_BLOB:
        code = "BLOB_REFUSED";
        msg = "the content-addressed store refused the record bytes";
        break;
    case ZENDP_ERR_ABSENT:
        code = "ENDPOINT_ABSENT";
        msg = "no record is filed for this identity at the current period "
              "or its predecessor — the publisher must republish each period";
        break;
    case ZENDP_ERR_DECODE:
        code = "DOC_DECODE_FAILED";
        msg = "the bytes are not a well-formed zid document";
        break;
    case ZENDP_ERR_VERIFY:
        code = "VERIFY_FAILED";
        msg = "the signature or the validity window failed — tampered, "
              "corrupted, expired, or not yet valid";
        break;
    case ZENDP_ERR_BODY:
        code = "NOT_AN_ENDPOINT_BODY";
        msg = "the document verified but its body is not a ZIDE endpoint "
              "record, or the record's own window has not opened yet";
        break;
    case ZENDP_ERR_KEY_MISMATCH:
        code = "KEY_MISMATCH";
        msg = "the record filed at this identity's address is signed by a "
              "different identity";
        break;
    case ZENDP_ERR_STALE:
        code = "STALE_SEQ";
        msg = "this record does not supersede the one already held — "
              "rotation requires a strictly higher seq; nothing was written";
        break;
    case ZENDP_ERR_FULL:
        code = "DIRECTORY_FULL";
        msg = "the endpoint directory has no free slot";
        break;
    case ZENDP_ERR_FETCH:
        code = "FETCH_REFUSED";
        msg = "the swarm refused the download";
        break;
    case ZENDP_ERR_NO_ANCHOR_LOOKUP:
        code = "NO_CHAIN_LOOKUP";
        msg = "nothing here can ask the chain about the signing key, so no "
              "record may be treated as anchored — this fails closed on "
              "purpose. Run this against a node datadir whose node.db is "
              "readable.";
        break;
    case ZENDP_ERR_ANCHOR_UNAVAILABLE:
        code = "CHAIN_UNAVAILABLE";
        msg = "the chain was asked about the signing key and the lookup "
              "itself failed — this is NOT the same as the chain saying no";
        break;
    case ZENDP_ERR_NOT_ANCHORED:
        code = "KEY_NOT_ANCHORED";
        msg = "the signing key was never anchored on-chain — the record is "
              "discarded, not stored";
        break;
    case ZENDP_ERR_ROTATED:
        code = "KEY_ROTATED";
        msg = "the signing key was rotated away — the record is discarded, "
              "not stored";
        break;
    case ZENDP_ERR_REVOKED:
        code = "KEY_REVOKED";
        msg = "the signing key was revoked — the record is discarded, not "
              "stored";
        break;
    case ZENDP_OK:
        return;
    }
    zec_fail(reply, code, "execute", msg, evidence);
}

/* ── seed loading (0600/0400, cleansed, never logged) ─────────────── */

static bool zec_read_seed(const char *path, uint8_t seed_out[32], char *err,
                          size_t err_size)
{
#if defined(_WIN32)
    uint8_t raw[65];
    size_t raw_size = 0;
    if (!zec_stable_read(path, raw, sizeof(raw), &raw_size, true)) {
        snprintf(err, err_size,
                 "seed file must be a stable private 64-hex file");
        return false;
    }
    ssize_t n = (ssize_t)raw_size;
#else
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(err, err_size, "cannot open seed file: %s", strerror(errno));
        return false;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        snprintf(err, err_size, "cannot stat seed file: %s", strerror(errno));
        close(fd);
        return false;
    }
    unsigned perms = (unsigned)(st.st_mode & 0777u);
    if (perms != 0600u && perms != 0400u) {
        snprintf(err, err_size,
                 "seed file perms are %03o — a master seed must be 0600 "
                 "(chmod 600 %s)", perms, path);
        close(fd);
        return false;
    }
    uint8_t raw[65];
    ssize_t n = read(fd, raw, sizeof(raw));
    close(fd);
#endif
    if (n < 64 || (n != 64 && !(n == 65 && raw[64] == '\n'))) {
        memory_cleanse(raw, sizeof(raw));
        snprintf(err, err_size,
                 "seed file must be exactly 64 hex chars (read %zd bytes)", n);
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

/* ── the record file: <datadir>/zcode/endpoints/<record_key>.zid ────
 *
 * Named by the BLINDED record key, holding the doc hex. This is the
 * ONLY durable output of this surface: the CLI process's in-memory
 * directory dies with it, and engine/composition/src/boot_endpoint_records.c reads
 * these files back into the node's live directory at start. Written
 * only after the record has verified. */

static void zec_hex32(const uint8_t in[32], char out[65])
{
    HexStr(in, 32, false, out, 65);
}

static bool zec_record_dir(const char *datadir, char *out, size_t out_size,
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
        snprintf(err, err_size, "unsafe private directory %s", dir);
        return false;
    }
#else
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        snprintf(err, err_size, "mkdir %s: %s", dir, strerror(errno));
        return false;
    }
#endif
    n = snprintf(out, out_size, "%s/zcode/endpoints", datadir);
    if (n <= 0 || (size_t)n >= out_size) {
        snprintf(err, err_size, "path too long under datadir");
        return false;
    }
#if defined(_WIN32)
    if (!platform_private_directory_ensure(out)) {
        snprintf(err, err_size, "unsafe private directory %s", out);
        return false;
    }
#else
    if (mkdir(out, 0700) != 0 && errno != EEXIST) {
        snprintf(err, err_size, "mkdir %s: %s", out, strerror(errno));
        return false;
    }
#endif
    return true;
}

static bool zec_write_record(const char *datadir, const char *key_hex,
                             const char *doc_hex, char *path_out,
                             size_t path_size, char *err, size_t err_size)
{
    char dir[1024];
    if (!zec_record_dir(datadir, dir, sizeof(dir), err, err_size))
        return false;
    int n = snprintf(path_out, path_size, "%s/%s.zid", dir, key_hex);
    if (n <= 0 || (size_t)n >= path_size) {
        snprintf(err, err_size, "path too long under datadir");
        return false;
    }
#if defined(_WIN32)
    struct platform_directory_transaction directory;
    struct platform_directory_child staged;
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&staged);
    char destination[80], temporary[80];
    int dn = snprintf(destination, sizeof(destination), "%s.zid", key_hex);
    int tn = snprintf(temporary, sizeof(temporary), ".endpoint.%ld.tmp",
                      (long)_getpid());
    bool staged_created = false;
    size_t len = strlen(doc_hex);
    bool ok = dn > 0 && (size_t)dn < sizeof(destination) &&
        tn > 0 && (size_t)tn < sizeof(temporary) &&
        platform_directory_transaction_open(&directory, dir) &&
        platform_directory_child_create(&directory, temporary, &staged) &&
        (staged_created = true) &&
        platform_directory_child_write_exact(&staged, doc_hex, len, 0) &&
        platform_directory_child_write_exact(&staged, "\n", 1, len) &&
        platform_directory_child_flush(&staged) &&
        platform_directory_child_replace(&directory, &staged, destination,
                                         false) &&
        platform_directory_transaction_flush(&directory);
    platform_directory_child_close(&staged);
    if (!ok && staged_created)
        (void)platform_directory_child_unlink(&directory, temporary, true);
    platform_directory_transaction_close(&directory);
    if (!ok) snprintf(err, err_size, "atomic endpoint write failed");
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
static bool zec_read_record(const char *datadir, const char *key_hex,
                            char *hex_out, size_t hex_size, char *path_out,
                            size_t path_size)
{
    int n = snprintf(path_out, path_size, "%s/zcode/endpoints/%s.zid",
                     datadir, key_hex);
    if (n <= 0 || (size_t)n >= path_size)
        return false;
#if defined(_WIN32)
    size_t size = 0;
    if (!zec_stable_read(path_out, hex_out, hex_size - 1u, &size, true) ||
        size == 0)
        return false;
    ssize_t r = (ssize_t)size;
#else
    int fd = open(path_out, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    ssize_t r = read(fd, hex_out, hex_size - 1);
    close(fd);
    if (r <= 0)
        return false;
#endif
    while (r > 0 && (hex_out[r - 1] == '\n' || hex_out[r - 1] == '\r' ||
                     hex_out[r - 1] == ' '))
        r--;
    hex_out[r] = '\0';
    return r > 0;
}

/* Even-length hex -> wire bytes. Returns 0 on any malformed input. */
static size_t zec_hex_to_wire(const char *hex, uint8_t *out, size_t out_size)
{
    size_t hex_len = hex ? strlen(hex) : 0;
    if (hex_len == 0 || (hex_len & 1u) != 0 || !IsHex(hex))
        return 0;
    if (hex_len / 2 > out_size)
        return 0;
    int n = ParseHex(hex, out, out_size);
    return n > 0 ? (size_t)n : 0;
}

/* The highest seq already ON DISK for this identity.
 *
 * Each CLI invocation is a fresh process, so the library's in-memory
 * monotonic-seq rule cannot see the previous publish — without this a
 * replayed lower seq could overwrite a newer record, which is exactly
 * what the seq rule exists to prevent. The record key rotates each
 * period, so the predecessor lives in a different file: both are
 * consulted. A file that does not decode, or that is signed by another
 * identity, is ignored rather than trusted — it cannot be OUR record. */
static bool zec_held_seq(const char *datadir, const uint8_t pk[32],
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
        zendp_record_key(key, pk, periods[i]);
        zec_hex32(key, key_hex);
        if (!zec_read_record(datadir, key_hex, hex, sizeof(hex), path,
                             sizeof(path)))
            continue;
        uint8_t wire[ZID_DOC_MAX];
        size_t wire_len = zec_hex_to_wire(hex, wire, sizeof(wire));
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

/* The twin of zdesc's verification-status block, and deliberately the
 * opposite claim: here the key was NOT supplied by the caller, it was
 * resolved against the chain, and only an ACTIVE anchor passes. */
/* `anchored` is the ANSWER for this particular reply, not a property of
 * the surface: publish may legitimately succeed with the anchor
 * transaction still unconfirmed, and a reply claiming chain_anchored
 * beside anchor_state:"unknown" would be a machine-readable lie.
 * verified_against is the MODEL and is always "chain_anchor" here —
 * that is the standing contrast with zcode.desc's "supplied_key". */
static void zec_push_verification_status(struct zcl_command_reply *reply,
                                         bool anchored)
{
    json_push_kv_bool(&reply->data, "chain_anchored", anchored);
    json_push_kv_str(&reply->data, "verified_against", "chain_anchor");
    json_push_kv_str(&reply->data, "verification_note",
                     "the signing key was taken from the record itself and "
                     "resolved against the on-chain identity projection — a "
                     "pass means the key is anchored and ACTIVE. A record "
                     "that fails is discarded, never stored.");
    json_push_kv_str(&reply->data, "hint_note",
                     "a verified record proves who signed it, not who "
                     "answers at the address — treat it as one more place "
                     "to try, never as a reason to exclude a peer");
}

static void zec_push_anchor(struct zcl_command_reply *reply,
                            const struct zendp_anchor *a)
{
    json_push_kv_str(&reply->data, "anchor_state",
                     zendp_anchor_state_string(a->state));
    json_push_kv_int(&reply->data, "anchor_height", a->anchor_height);
    json_push_kv_int(&reply->data, "anchor_updated_height",
                     a->updated_height);
}

static void zec_push_endpoint_into(struct json_value *obj,
                                   const struct zendp *ep)
{
    json_push_kv_int(obj, "flags", ep->flags);
    json_push_kv_bool(obj, "has_onion", (ep->flags & ZENDP_HAS_ONION) != 0);
    json_push_kv_bool(obj, "has_ipv4", (ep->flags & ZENDP_HAS_IPV4) != 0);
    json_push_kv_bool(obj, "has_ipv6", (ep->flags & ZENDP_HAS_IPV6) != 0);
    if (ep->flags & ZENDP_HAS_ONION) {
        json_push_kv_str(obj, "onion", ep->onion);
        json_push_kv_int(obj, "onion_port", ep->onion_port);
    }
    if (ep->flags & ZENDP_HAS_IPV4) {
        char buf[PLATFORM_IPV4_ADDRESS_TEXT_SIZE];
        if (platform_socket_format_address(AF_INET, ep->ipv4, buf, sizeof(buf)))
            json_push_kv_str(obj, "ipv4", buf);
        json_push_kv_int(obj, "ipv4_port", ep->ipv4_port);
    }
    if (ep->flags & ZENDP_HAS_IPV6) {
        char buf[PLATFORM_IPV6_ADDRESS_TEXT_SIZE];
        if (platform_socket_format_address(AF_INET6, ep->ipv6, buf, sizeof(buf)))
            json_push_kv_str(obj, "ipv6", buf);
        json_push_kv_int(obj, "ipv6_port", ep->ipv6_port);
    }
    json_push_kv_int(obj, "services", (int64_t)ep->services);
    json_push_kv_int(obj, "height", (int64_t)ep->height);
    json_push_kv_int(obj, "not_before", (int64_t)ep->not_before);
}

static void zec_push_record(struct zcl_command_reply *reply,
                            const struct zid_doc *doc,
                            const struct zendp *ep)
{
    char pk_hex[65];
    zec_hex32(doc->master_pubkey, pk_hex);
    json_push_kv_str(&reply->data, "master_pubkey", pk_hex);
    json_push_kv_int(&reply->data, "seq", (int64_t)doc->seq);
    json_push_kv_int(&reply->data, "expiry", (int64_t)doc->expiry);

    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    zec_push_endpoint_into(&obj, ep);
    json_push_kv(&reply->data, "endpoint", &obj);
    json_free(&obj);
}

/* ── input -> struct zendp ─────────────────────────────────────────── */

/* Build the record body from operator input. Every transport is
 * optional and "none" is not: a record naming no way to reach anything
 * is refused here by name rather than handed to the library to reject
 * with a less specific message. */
static bool zec_build_endpoint(const struct json_value *in,
                               struct zcl_command_reply *reply,
                               const char *cmd, int64_t now,
                               struct zendp *ep)
{
    memset(ep, 0, sizeof(*ep));

    const char *onion = zec_input_str(in, "onion");
    if (onion && onion[0]) {
        if (!zdesc_onion_valid(onion)) {
            zec_fail(reply, "BAD_ONION", "normalize",
                     "onion must be a 56-character base32 v3 hostname "
                     "ending in .onion", cmd);
            return false;
        }
        int64_t port = zec_input_int(in, "onion_port", 8033);
        if (port <= 0 || port > 65535) {
            zec_fail(reply, "BAD_PORT", "normalize",
                     "onion_port must be 1..65535", cmd);
            return false;
        }
        snprintf(ep->onion, sizeof(ep->onion), "%s", onion);
        ep->onion_port = (uint16_t)port;
        ep->flags |= ZENDP_HAS_ONION;
    }

    const char *ipv4 = zec_input_str(in, "ipv4");
    if (ipv4 && ipv4[0]) {
        if (platform_socket_parse_address(AF_INET, ipv4, ep->ipv4) != 1) {
            zec_fail(reply, "BAD_IPV4", "normalize",
                     "ipv4 must be a dotted-quad address", ipv4);
            return false;
        }
        int64_t port = zec_input_int(in, "ipv4_port", 8033);
        if (port <= 0 || port > 65535) {
            zec_fail(reply, "BAD_PORT", "normalize",
                     "ipv4_port must be 1..65535", cmd);
            return false;
        }
        ep->ipv4_port = (uint16_t)port;
        ep->flags |= ZENDP_HAS_IPV4;
    }

    const char *ipv6 = zec_input_str(in, "ipv6");
    if (ipv6 && ipv6[0]) {
        if (platform_socket_parse_address(AF_INET6, ipv6, ep->ipv6) != 1) {
            zec_fail(reply, "BAD_IPV6", "normalize",
                     "ipv6 must be a colon-separated address", ipv6);
            return false;
        }
        int64_t port = zec_input_int(in, "ipv6_port", 8033);
        if (port <= 0 || port > 65535) {
            zec_fail(reply, "BAD_PORT", "normalize",
                     "ipv6_port must be 1..65535", cmd);
            return false;
        }
        ep->ipv6_port = (uint16_t)port;
        ep->flags |= ZENDP_HAS_IPV6;
    }

    if (ep->flags == 0) {
        zec_fail(reply, "NO_ENDPOINT", "normalize",
                 "a record must name at least one way to reach this node — "
                 "pass onion, ipv4 or ipv6", cmd);
        return false;
    }

    int64_t services = zec_input_int(in, "services", 0);
    int64_t height = zec_input_int(in, "height", 0);
    if (services < 0 || height < 0 || height > (int64_t)UINT32_MAX) {
        zec_fail(reply, "BAD_CLAIM", "normalize",
                 "services and height must be non-negative, and height must "
                 "fit 32 bits", cmd);
        return false;
    }
    ep->services = (uint64_t)services;
    ep->height = (uint32_t)height;

    int64_t not_before = zec_input_int(in, "not_before", 0);
    ep->not_before = (uint64_t)(not_before > 0 ? not_before : now);

    if (!zendp_valid(ep)) {
        zec_fail(reply, "BAD_ENDPOINT", "normalize",
                 "the record fails the shape rule — a claimed address must "
                 "be non-zero and carry a non-zero port", cmd);
        return false;
    }
    return true;
}

/* Load record wire bytes from --doc=<hex> or --file=<path>. */
static size_t zec_load_doc_wire(const struct json_value *in,
                                struct zcl_command_reply *reply,
                                const char *cmd, uint8_t *out,
                                size_t out_size)
{
    const char *doc_hex = zec_input_str(in, "doc");
    static char file_hex[ZID_DOC_MAX * 2 + 2];
    if (!doc_hex || !doc_hex[0]) {
        const char *path = zec_input_str(in, "file");
        if (!path || !path[0]) {
            zec_fail(reply, "MISSING_DOC", "normalize",
                     "pass the record as --doc=<hex> or --file=<path to a "
                     "saved .zid>", cmd);
            return 0;
        }
#if defined(_WIN32)
        size_t file_size = 0;
        if (!zec_stable_read(path, file_hex, sizeof(file_hex) - 1u,
                             &file_size, false) || file_size == 0) {
            zec_fail(reply, "FILE_UNREADABLE", "normalize",
                     "record file is empty, unsafe, unstable or unreadable",
                     path);
            return 0;
        }
        ssize_t r = (ssize_t)file_size;
#else
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            zec_fail(reply, "FILE_UNREADABLE", "normalize",
                     "cannot open the record file", path);
            return 0;
        }
        ssize_t r = read(fd, file_hex, sizeof(file_hex) - 1);
        close(fd);
        if (r <= 0) {
            zec_fail(reply, "FILE_UNREADABLE", "normalize",
                     "the record file is empty", path);
            return 0;
        }
#endif
        while (r > 0 && (file_hex[r - 1] == '\n' || file_hex[r - 1] == '\r' ||
                         file_hex[r - 1] == ' '))
            r--;
        file_hex[r] = '\0';
        doc_hex = file_hex;
    }
    size_t wire_len = zec_hex_to_wire(doc_hex, out, out_size);
    if (wire_len == 0) {
        zec_fail(reply, "BAD_DOC_HEX", "normalize",
                 "the record must be even-length hex that fits one zid "
                 "document", cmd);
        return 0;
    }
    return wire_len;
}

/* A directory big enough to hold ZENDP_DIR_MAX docs is ~45 KB, so it is
 * file-static rather than a stack frame. Safe: each CLI invocation runs
 * exactly one handler on one thread and then exits. */
static struct zendp_directory g_cli_dir;

/* ── the chain binding, in a CLI process ───────────────────────────
 *
 * The node registers the anchor lookup at boot
 * (engine/composition/src/boot_onion_discovery.c). A CLI invocation is a different
 * process that never runs boot, so without this every verify would come
 * back NO_CHAIN_LOOKUP — fail-closed, correct, and useless. So the CLI
 * opens <datadir>/node.db READONLY for itself, the same pre-flight
 * pattern native_zdir_command.c uses.
 *
 * The VERDICT MAPPING is not duplicated: boot_endpoint_anchor_from_db()
 * is the one implementation and both processes call it. A CLI-local
 * copy of "which status literal means ACTIVE" would be a second answer
 * to the only question this subsystem asks.
 *
 * A missing or unreadable node.db is NOT quietly treated as "no such
 * identity" — the lookup returns false, the library reports
 * ZENDP_ERR_ANCHOR_UNAVAILABLE, and the operator is told the chain
 * could not be asked. */
static struct node_db g_cli_ndb;

static bool zec_cli_anchor_lookup(void *ctx, const uint8_t pubkey[32],
                                  struct zendp_anchor *out)
{
    (void)ctx;
    return boot_endpoint_anchor_from_db(&g_cli_ndb, pubkey, out);
}

/* Returns true when the chain can be asked. On false the caller still
 * proceeds: the library names the refusal, which is more useful than a
 * bespoke error here. */
static bool zec_open_chain(const char *datadir)
{
    if (g_cli_ndb.open)
        return true;
    if (!datadir || !datadir[0])
        return false;
    /* Read-only open (command/native_command.h): this is an optional chain
     * consult, so a false return is never reported as an answer — the
     * caller proceeds and the library names the refusal itself. */
    sqlite3 *db = NULL;
    if (zcl_native_node_db_open_readonly(datadir, &db, &g_cli_ndb, NULL, 0) !=
        ZCL_NODE_DB_RO_OK)
        return false;
    zendp_set_anchor_lookup(zec_cli_anchor_lookup, NULL);
    return true;
}

static void zec_close_chain(void)
{
    zendp_set_anchor_lookup(NULL, NULL);
    zcl_native_node_db_close_readonly(NULL, &g_cli_ndb);
}

/* ── zcode.endpoint.publish ────────────────────────────────────────── */

void zcl_native_handle_zendp_publish(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const struct json_value *in = request->input;
    const char *cmd = "zcode.endpoint.publish";

    const char *seed_file = zec_input_str(in, "seed_file");
    if (!seed_file || !seed_file[0]) {
        zec_fail(reply, "MISSING_SEED_FILE", "normalize",
                 "seed_file must name a file holding the 32-byte identity "
                 "master seed as 64 hex chars, mode 0600", cmd);
        return;
    }

    int64_t now = zec_input_int(in, "now", 0);
    if (now <= 0)
        now = platform_time_wall_unix();

    struct zendp ep;
    if (!zec_build_endpoint(in, reply, cmd, now, &ep))
        return;

    int64_t seq = zec_input_int(in, "seq", 1);
    if (seq <= 0) {
        zec_fail(reply, "BAD_SEQ", "normalize",
                 "seq must be a positive whole number and must increase on "
                 "every republish", cmd);
        return;
    }
    int64_t expiry_in = zec_input_int(in, "expiry", 0);
    /* The default is derived UNSIGNED. ep.not_before is operator input
     * and can be as large as INT64_MAX, so
     * `(int64_t)ep.not_before + ZEC_DEFAULT_VALIDITY_SECONDS` is a
     * signed overflow — undefined behaviour, not a wrap you can reason
     * about. ep.not_before is <= INT64_MAX by construction above, so the
     * unsigned add below cannot wrap uint64_t. */
    uint64_t expiry = expiry_in > 0
                          ? (uint64_t)expiry_in
                          : ep.not_before +
                                (uint64_t)ZEC_DEFAULT_VALIDITY_SECONDS;
    /* Both window rules come from zendp_window_check — the same function
     * the signer and every verifier call. Nothing about the window is
     * re-derived here; only the operator-facing wording is local. */
    switch (zendp_window_check(ep.not_before, expiry)) {
    case ZENDP_WINDOW_NEVER_OPENS:
        zec_fail(reply, "BAD_WINDOW", "normalize",
                 "expiry must be after not_before — a window that never "
                 "opens is a publisher bug, not a verifier's problem", cmd);
        return;
    case ZENDP_WINDOW_TOO_LONG:
        zec_fail(reply, "WINDOW_TOO_LONG", "normalize",
                 zec_window_too_long_message(), cmd);
        return;
    case ZENDP_WINDOW_OK:
        break;
    }

    const char *datadir = zec_datadir(request);
    if (!datadir) {
        zec_fail(reply, "NO_DATADIR", "normalize",
                 "no datadir resolved — pass --datadir; the record blob and "
                 "its record file are written under <datadir>/zcode/", cmd);
        return;
    }

    uint8_t seed[32];
    char err[512];
    if (!zec_read_seed(seed_file, seed, err, sizeof(err))) {
        zec_fail(reply, "BAD_SEED_FILE", "normalize", err, seed_file);
        return;
    }

    /* Replay defence across invocations, checked BEFORE the store is
     * touched so a refused republish writes nothing at all. */
    uint8_t pk[32], sk[32];
    ed25519_keypair(pk, sk, seed);
    memory_cleanse(sk, sizeof(sk));
    uint64_t held = 0;
    if (zec_held_seq(datadir, pk, zdesc_period_at((uint64_t)now), &held) &&
        (uint64_t)seq <= held) {
        memory_cleanse(seed, sizeof(seed));
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "seq %lld does not supersede the endpoint record already "
                 "filed for this identity (seq %llu) — rotation needs a "
                 "strictly higher seq; nothing was written",
                 (long long)seq, (unsigned long long)held);
        zec_fail(reply, "STALE_SEQ", "execute", msg, cmd);
        return;
    }

    struct vcs_package_store *store =
        vcs_package_store_open(datadir, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    if (!store) {
        memory_cleanse(seed, sizeof(seed));
        zec_fail(reply, "STORE_UNAVAILABLE", "execute",
                 "cannot open the content-addressed package store under "
                 "<datadir>/zcode", datadir);
        return;
    }

    zendp_directory_init(&g_cli_dir);
    (void)zec_open_chain(datadir);
    uint8_t root[32], pubkey[32];
    enum zendp_result r =
        zendp_publish_to(store, &g_cli_dir, &ep, (uint64_t)seq,
                         (uint64_t)expiry, seed, (uint64_t)now, root, pubkey);
    zec_close_chain();
    memory_cleanse(seed, sizeof(seed));
    vcs_package_store_close(store);
    if (r != ZENDP_OK) {
        zec_fail_result(reply, r, cmd);
        return;
    }

    const struct zendp_entry *entry = NULL;
    if (!zendp_directory_find(&g_cli_dir, pubkey, &entry) || !entry) {
        zec_fail(reply, "DIRECTORY_LOST", "execute",
                 "the record was stored but its directory entry is missing",
                 cmd);
        return;
    }
    struct zid_doc doc = entry->doc;
    uint64_t period = entry->period;
    struct zendp_anchor anchor = entry->anchor;
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

    char key_hex[65], root_hex[65];
    zec_hex32(record_key, key_hex);
    zec_hex32(root, root_hex);

    char saved_path[1200];
    char save_err[512] = {0};
    bool saved = zec_write_record(datadir, key_hex, doc_hex, saved_path,
                                  sizeof(saved_path), save_err,
                                  sizeof(save_err));

    json_push_kv_str(&reply->data, "doc_hex", doc_hex);
    json_push_kv_int(&reply->data, "doc_bytes", (int64_t)wire_len);
    json_push_kv_str(&reply->data, "root", root_hex);
    json_push_kv_str(&reply->data, "record_key", key_hex);
    json_push_kv_int(&reply->data, "period", (int64_t)period);
    json_push_kv_int(&reply->data, "period_seconds", ZDESC_PERIOD_SECONDS);
    zec_push_record(reply, &doc, &ep);
    zec_push_anchor(reply, &anchor);

    /* Publishing does not REQUIRE an anchor — the anchor transaction can
     * still be unconfirmed — but an unanchored record is never offered
     * to peer discovery, so say so plainly instead of implying success. */
    bool discoverable = anchor.state == ZENDP_ANCHOR_ACTIVE;
    json_push_kv_bool(&reply->data, "discoverable", discoverable);
    if (!discoverable)
        json_push_kv_str(&reply->data, "discoverable_note",
                         "the signing key is not ACTIVE on-chain, so this "
                         "record is stored and addressable but will NOT be "
                         "offered to peer discovery — anchor the identity "
                         "first, then republish with a higher seq");
    zec_push_verification_status(reply, discoverable);
    json_push_kv_bool(&reply->data, "saved", saved);
    if (saved)
        json_push_kv_str(&reply->data, "saved_path", saved_path);
    else
        json_push_kv_str(&reply->data, "save_error", save_err);
    json_push_kv_str(&reply->data, "next",
                     "the node loads and re-verifies filed records at start. "
                     "Nothing republishes for you: the record key rotates "
                     "every period, so run this again each period with a "
                     "strictly higher seq. No timer and no background "
                     "publisher exists — announcing this node is always your "
                     "choice.");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── zcode.endpoint.verify ─────────────────────────────────────────── */

/* Read-only twin of accept: runs the identical pipeline (including the
 * chain check) into a directory nobody reads, and writes NO file. The
 * point is a dry run that cannot change node state. */
void zcl_native_handle_zendp_verify(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const struct json_value *in = request->input;
    const char *cmd = "zcode.endpoint.verify";

    uint8_t wire[ZID_DOC_MAX];
    size_t wire_len = zec_load_doc_wire(in, reply, cmd, wire, sizeof(wire));
    if (wire_len == 0)
        return;

    int64_t now = zec_input_int(in, "now", 0);
    if (now <= 0)
        now = platform_time_wall_unix();

    zendp_directory_init(&g_cli_dir);
    (void)zec_open_chain(zec_datadir(request));
    struct zendp ep;
    uint8_t pubkey[32];
    enum zendp_result r = zendp_accept(&g_cli_dir, wire, wire_len,
                                       (uint64_t)now, &ep, pubkey);
    zec_close_chain();
    if (r != ZENDP_OK) {
        zec_fail_result(reply, r, cmd);
        return;
    }
    struct zid_doc doc;
    if (!zid_doc_decode(&doc, wire, wire_len)) {
        zec_fail(reply, "DOC_DECODE_FAILED", "execute",
                 "the record verified but would not re-decode", cmd);
        return;
    }
    const struct zendp_entry *entry = NULL;
    struct zendp_anchor anchor = {0};
    if (zendp_directory_find(&g_cli_dir, pubkey, &entry) && entry)
        anchor = entry->anchor;

    uint64_t period = zdesc_period_at((uint64_t)now);
    uint8_t record_key[32];
    char key_hex[65];
    zendp_record_key(record_key, doc.master_pubkey, period);
    zec_hex32(record_key, key_hex);

    json_push_kv_bool(&reply->data, "valid", true);
    json_push_kv_int(&reply->data, "now", now);
    json_push_kv_str(&reply->data, "record_key", key_hex);
    json_push_kv_int(&reply->data, "period", (int64_t)period);
    json_push_kv_bool(&reply->data, "stored", false);
    json_push_kv_str(&reply->data, "stored_note",
                     "verify never writes — use `zcode endpoint accept` to "
                     "file a record this node should load at start");
    zec_push_record(reply, &doc, &ep);
    zec_push_anchor(reply, &anchor);
    zec_push_verification_status(reply, anchor.state == ZENDP_ANCHOR_ACTIVE);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── zcode.endpoint.accept ─────────────────────────────────────────── */

/* THE RECEIVING SIDE. Peer-supplied bytes are run through the whole
 * pipeline — decode, signature, doc window, ZIDE body, record window,
 * and the on-chain anchor — and the record file is written ONLY on
 * ZENDP_OK. Every refusal returns before the write, so a record that
 * does not verify against a chain-anchored identity leaves nothing on
 * disk and can never be read back as if it had been believed. */
void zcl_native_handle_zendp_accept(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const struct json_value *in = request->input;
    const char *cmd = "zcode.endpoint.accept";

    uint8_t wire[ZID_DOC_MAX];
    size_t wire_len = zec_load_doc_wire(in, reply, cmd, wire, sizeof(wire));
    if (wire_len == 0)
        return;

    const char *datadir = zec_datadir(request);
    if (!datadir) {
        zec_fail(reply, "NO_DATADIR", "normalize",
                 "no datadir resolved — pass --datadir; accepted records are "
                 "filed under <datadir>/zcode/endpoints/", cmd);
        return;
    }

    int64_t now = zec_input_int(in, "now", 0);
    if (now <= 0)
        now = platform_time_wall_unix();

    zendp_directory_init(&g_cli_dir);
    (void)zec_open_chain(datadir);
    struct zendp ep;
    uint8_t pubkey[32];
    enum zendp_result r = zendp_accept(&g_cli_dir, wire, wire_len,
                                       (uint64_t)now, &ep, pubkey);
    zec_close_chain();
    if (r != ZENDP_OK) {
        /* DISCARD. Nothing has been written; nothing will be. */
        zec_fail_result(reply, r, cmd);
        return;
    }

    struct zid_doc doc;
    if (!zid_doc_decode(&doc, wire, wire_len)) {
        zec_fail(reply, "DOC_DECODE_FAILED", "execute",
                 "the record verified but would not re-decode", cmd);
        return;
    }

    /* Do not let an older record overwrite a newer one already on file. */
    uint64_t period = zdesc_period_at((uint64_t)now);
    uint64_t held = 0;
    if (zec_held_seq(datadir, doc.master_pubkey, period, &held) &&
        doc.seq <= held) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "the offered record's seq %llu does not supersede the one "
                 "already filed for this identity (seq %llu) — the file is "
                 "unchanged",
                 (unsigned long long)doc.seq, (unsigned long long)held);
        zec_fail(reply, "STALE_SEQ", "execute", msg, cmd);
        return;
    }

    const struct zendp_entry *entry = NULL;
    struct zendp_anchor anchor = {0};
    uint8_t record_key[32];
    if (zendp_directory_find(&g_cli_dir, pubkey, &entry) && entry) {
        anchor = entry->anchor;
        memcpy(record_key, entry->record_key, 32);
    } else {
        zendp_record_key(record_key, doc.master_pubkey, period);
    }

    char doc_hex[ZID_DOC_MAX * 2 + 1];
    HexStr(wire, wire_len, false, doc_hex, sizeof(doc_hex));
    char key_hex[65];
    zec_hex32(record_key, key_hex);

    char saved_path[1200];
    char save_err[512] = {0};
    if (!zec_write_record(datadir, key_hex, doc_hex, saved_path,
                          sizeof(saved_path), save_err, sizeof(save_err))) {
        zec_fail(reply, "SAVE_FAILED", "execute", save_err, datadir);
        return;
    }

    json_push_kv_bool(&reply->data, "accepted", true);
    json_push_kv_int(&reply->data, "now", now);
    json_push_kv_str(&reply->data, "record_key", key_hex);
    json_push_kv_int(&reply->data, "period", (int64_t)period);
    json_push_kv_bool(&reply->data, "stored", true);
    json_push_kv_str(&reply->data, "saved_path", saved_path);
    zec_push_record(reply, &doc, &ep);
    zec_push_anchor(reply, &anchor);
    zec_push_verification_status(reply, anchor.state == ZENDP_ANCHOR_ACTIVE);
    json_push_kv_str(&reply->data, "next",
                     "this node re-verifies every filed record against the "
                     "chain at start, so a key revoked between now and then "
                     "is dropped rather than dialed.");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── zcode.endpoint.resolve ────────────────────────────────────────── */

void zcl_native_handle_zendp_resolve(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const struct json_value *in = request->input;
    const char *cmd = "zcode.endpoint.resolve";

    const char *pk_hex = zec_input_str(in, "pubkey");
    uint8_t pubkey[32];
    if (!pk_hex || strlen(pk_hex) != 64 || !IsHex(pk_hex) ||
        ParseHex(pk_hex, pubkey, 32) != 32) {
        zec_fail(reply, "BAD_PUBKEY", "normalize",
                 "pubkey must be exactly 64 hex chars (the 32-byte identity "
                 "master public key)", cmd);
        return;
    }
    const char *datadir = zec_datadir(request);
    if (!datadir) {
        zec_fail(reply, "NO_DATADIR", "normalize",
                 "no datadir resolved — pass --datadir; records are read "
                 "from <datadir>/zcode/endpoints/", cmd);
        return;
    }

    int64_t now = zec_input_int(in, "now", 0);
    if (now <= 0)
        now = platform_time_wall_unix();

    /* THE BOUNDARY RULE: current period first, then the one before, so a
     * publisher on the other side of midnight is still findable. */
    uint64_t period = zdesc_period_at((uint64_t)now);
    uint64_t used = period;
    uint8_t record_key[32];
    char key_hex[65], path[1200];
    static char doc_hex[ZID_DOC_MAX * 2 + 2];
    zendp_record_key(record_key, pubkey, period);
    zec_hex32(record_key, key_hex);
    bool found = zec_read_record(datadir, key_hex, doc_hex, sizeof(doc_hex),
                                 path, sizeof(path));
    if (!found && period > 0) {
        used = zdesc_period_prev(period);
        zendp_record_key(record_key, pubkey, used);
        zec_hex32(record_key, key_hex);
        found = zec_read_record(datadir, key_hex, doc_hex, sizeof(doc_hex),
                                path, sizeof(path));
    }
    if (!found) {
        zec_fail_result(reply, ZENDP_ERR_ABSENT, cmd);
        return;
    }

    uint8_t wire[ZID_DOC_MAX];
    size_t wire_len = zec_hex_to_wire(doc_hex, wire, sizeof(wire));
    if (wire_len == 0) {
        zec_fail(reply, "BAD_DOC_HEX", "execute",
                 "the record file does not hold even-length hex", path);
        return;
    }

    /* Re-run the WHOLE pipeline on the bytes that came off disk — the
     * file is a witness, never the authority for what a record says. */
    zendp_directory_init(&g_cli_dir);
    (void)zec_open_chain(datadir);
    struct zendp ep;
    uint8_t got_pk[32];
    enum zendp_result r = zendp_accept(&g_cli_dir, wire, wire_len,
                                       (uint64_t)now, &ep, got_pk);
    zec_close_chain();
    if (r != ZENDP_OK) {
        zec_fail_result(reply, r, path);
        return;
    }
    if (memcmp(got_pk, pubkey, 32) != 0) {
        zec_fail_result(reply, ZENDP_ERR_KEY_MISMATCH, path);
        return;
    }
    struct zid_doc doc;
    if (!zid_doc_decode(&doc, wire, wire_len)) {
        zec_fail(reply, "DOC_DECODE_FAILED", "execute",
                 "the record verified but would not re-decode", path);
        return;
    }
    const struct zendp_entry *entry = NULL;
    struct zendp_anchor anchor = {0};
    if (zendp_directory_find(&g_cli_dir, got_pk, &entry) && entry)
        anchor = entry->anchor;

    json_push_kv_bool(&reply->data, "valid", true);
    json_push_kv_int(&reply->data, "now", now);
    json_push_kv_str(&reply->data, "record_key", key_hex);
    json_push_kv_int(&reply->data, "period", (int64_t)period);
    json_push_kv_int(&reply->data, "period_used", (int64_t)used);
    json_push_kv_bool(&reply->data, "previous_period_fallback",
                      used != period);
    json_push_kv_str(&reply->data, "source_path", path);
    json_push_kv_str(&reply->data, "doc_hex", doc_hex);
    zec_push_record(reply, &doc, &ep);
    zec_push_anchor(reply, &anchor);
    zec_push_verification_status(reply, anchor.state == ZENDP_ANCHOR_ACTIVE);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── zcode.endpoint.list ───────────────────────────────────────────── */

/* Every filed record, each re-verified against the chain right now.
 * This is the same work engine/composition/src/boot_endpoint_records.c does at node
 * start, so it answers "which of these will my node actually use, and
 * why not the rest" without restarting anything. */
void zcl_native_handle_zendp_list(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const struct json_value *in = request->input;
    const char *cmd = "zcode.endpoint.list";

    const char *datadir = zec_datadir(request);
    if (!datadir) {
        zec_fail(reply, "NO_DATADIR", "normalize",
                 "no datadir resolved — pass --datadir; records are read "
                 "from <datadir>/zcode/endpoints/", cmd);
        return;
    }

    int64_t now = zec_input_int(in, "now", 0);
    if (now <= 0)
        now = platform_time_wall_unix();

    char dir_path[1200];
    int n = snprintf(dir_path, sizeof(dir_path), "%s/zcode/endpoints",
                     datadir);
    if (n <= 0 || (size_t)n >= sizeof(dir_path)) {
        zec_fail(reply, "NO_DATADIR", "normalize",
                 "path too long under datadir", datadir);
        return;
    }

    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    int usable = 0, unusable = 0, scanned = 0;

    DIR *d = opendir(dir_path);
    if (d) {
        zendp_directory_init(&g_cli_dir);
        (void)zec_open_chain(datadir);
        struct dirent *de;
        while ((de = readdir(d)) != NULL && scanned < ZEC_SCAN_MAX) {
            size_t len = strlen(de->d_name);
            if (len < 5 || strcmp(de->d_name + len - 4, ".zid") != 0)
                continue;
            scanned++;
            char key_hex[65];
            if (len - 4 != 64)
                continue;
            memcpy(key_hex, de->d_name, 64);
            key_hex[64] = '\0';

            static char hex[ZID_DOC_MAX * 2 + 2];
            char path[1200];
            struct json_value row;
            json_init(&row);
            json_set_object(&row);
            json_push_kv_str(&row, "record_key", key_hex);

            if (!zec_read_record(datadir, key_hex, hex, sizeof(hex), path,
                                 sizeof(path))) {
                json_push_kv_bool(&row, "usable", false);
                json_push_kv_str(&row, "reason", "the file could not be read");
                unusable++;
                json_push_back(&rows, &row);
                json_free(&row);
                continue;
            }
            uint8_t wire[ZID_DOC_MAX];
            size_t wire_len = zec_hex_to_wire(hex, wire, sizeof(wire));
            if (wire_len == 0) {
                json_push_kv_bool(&row, "usable", false);
                json_push_kv_str(&row, "reason",
                                 "the file does not hold even-length hex");
                unusable++;
                json_push_back(&rows, &row);
                json_free(&row);
                continue;
            }
            struct zendp ep;
            uint8_t pubkey[32];
            enum zendp_result r = zendp_accept(&g_cli_dir, wire, wire_len,
                                               (uint64_t)now, &ep, pubkey);
            if (r != ZENDP_OK) {
                json_push_kv_bool(&row, "usable", false);
                json_push_kv_str(&row, "reason", zendp_result_string(r));
                json_push_kv_str(&row, "outcome",
                                 "discarded — this record will not be "
                                 "loaded and will not be dialed");
                unusable++;
            } else {
                char pk_hex[65];
                zec_hex32(pubkey, pk_hex);
                json_push_kv_bool(&row, "usable", true);
                json_push_kv_str(&row, "master_pubkey", pk_hex);
                zec_push_endpoint_into(&row, &ep);
                usable++;
            }
            json_push_back(&rows, &row);
            json_free(&row);
        }
        zec_close_chain();
        closedir(d);
    }

    json_push_kv(&reply->data, "records", &rows);
    json_free(&rows);
    json_push_kv_int(&reply->data, "now", now);
    json_push_kv_str(&reply->data, "source_dir", dir_path);
    json_push_kv_int(&reply->data, "scanned", scanned);
    json_push_kv_int(&reply->data, "usable", usable);
    json_push_kv_int(&reply->data, "unusable", unusable);
    json_push_kv_int(&reply->data, "directory_capacity", ZENDP_DIR_MAX);
    zec_push_verification_status(reply, usable > 0);
    json_push_kv_str(&reply->data, "note",
                     "this is the same check the node runs at start: a "
                     "record whose key is not ACTIVE on-chain is discarded, "
                     "not kept in a lesser state");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
