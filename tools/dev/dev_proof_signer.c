/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Per-box Ed25519 identity and signer allowlist for push-proof
 *          receipts. See dev_proof_signer.h for the contract. */

#include "dev_proof_signer.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "crypto/ed25519.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "platform/state_root.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIGNER_DOMAIN "dev-proof-signer"
#define SIGNER_SEED_BYTES 32u
#define SIGNER_DIR_LEAF "proof-signer"
#define SIGNER_KEY_LEAF "signer.ed25519"
#define SIGNER_ALLOW_LEAF "signers.allow"
/* One trusted box is one 65-byte line, so 64 KiB is roughly a thousand of
 * them. The cap bounds the one allocation this module makes and refuses an
 * accidental multi-megabyte paste instead of swallowing it. */
#define SIGNER_ALLOW_MAX_BYTES 65536u

#define WHY_UNREADABLE ZCL_DEV_PROOF_SIGNER_WHY_KEY_UNREADABLE
#define WHY_UNKNOWN ZCL_DEV_PROOF_SIGNER_WHY_SIGNER_UNKNOWN
#define WHY_SIGNATURE ZCL_DEV_PROOF_SIGNER_WHY_SIGNATURE_INVALID
#define WHY_ARGUMENTS ZCL_DEV_PROOF_SIGNER_WHY_ARGUMENTS_INVALID

enum signer_seed_state {
    SIGNER_SEED_OK = 0,
    SIGNER_SEED_ABSENT,
    SIGNER_SEED_UNREADABLE,
};

static void signer_why(const char **why, const char *token)
{
    if (why) *why = token;
}

static bool signer_dir(char *out, size_t cap)
{
    char root[ZCL_DEV_PROOF_SIGNER_PATH_MAX];
    if (!out || !platform_state_root(root, sizeof(root)))
        return false;
    int n = snprintf(out, cap, "%s/%s", root, SIGNER_DIR_LEAF);
    return n > 0 && (size_t)n < cap && platform_private_directory_ensure(out);
}

bool zcl_dev_proof_signer_paths(char *key_path, size_t key_cap,
                                char *allow_path, size_t allow_cap)
{
    char dir[ZCL_DEV_PROOF_SIGNER_PATH_MAX];
    if (!signer_dir(dir, sizeof(dir)))
        return false;
    if (key_path) {
        int n = snprintf(key_path, key_cap, "%s/%s", dir, SIGNER_KEY_LEAF);
        if (n <= 0 || (size_t)n >= key_cap)
            return false;
    }
    if (allow_path) {
        int n = snprintf(allow_path, allow_cap, "%s/%s", dir,
                         SIGNER_ALLOW_LEAF);
        if (n <= 0 || (size_t)n >= allow_cap)
            return false;
    }
    return true;
}

/* Read the 32-byte seed. A path that cannot be opened at all reports ABSENT:
 * the caller that wants a key then creates one (and an O_EXCL create is what
 * turns a real permission problem into UNREADABLE on the retry), while the
 * caller that only verifies correctly concludes this box has no key yet. A
 * file that opens but is not a private 32-byte regular file is UNREADABLE —
 * that is the wrong-mode, wrong-size and truncated-write case. */
static enum signer_seed_state signer_seed_read(const char *path,
                                               uint8_t seed[SIGNER_SEED_BYTES])
{
    struct platform_positioned_file file;
    uint64_t size = 0;
    platform_positioned_file_init(&file);
    memset(seed, 0, SIGNER_SEED_BYTES);
    if (!platform_positioned_file_open(&file, path))
        return SIGNER_SEED_ABSENT;
    bool ok = platform_positioned_file_is_current_user_only(&file) &&
              platform_positioned_file_size(&file, &size) &&
              size == SIGNER_SEED_BYTES &&
              platform_positioned_file_read(&file, seed, SIGNER_SEED_BYTES,
                                            0) == (int64_t)SIGNER_SEED_BYTES;
    platform_positioned_file_close(&file);
    if (ok)
        return SIGNER_SEED_OK;
    memory_cleanse(seed, SIGNER_SEED_BYTES);
    return SIGNER_SEED_UNREADABLE;
}

static bool signer_seed_create(const char *path,
                               uint8_t seed[SIGNER_SEED_BYTES])
{
    struct platform_private_file file;
    platform_private_file_init(&file);
    if (!rng_fill(seed, SIGNER_SEED_BYTES)) {
        memory_cleanse(seed, SIGNER_SEED_BYTES);
        LOG_FAIL(SIGNER_DOMAIN,
                 "host CSPRNG refused a %u-byte signing seed; refusing to "
                 "invent one", SIGNER_SEED_BYTES);
    }
    if (!platform_private_file_create(path, &file))
        return false; /* already there, or unwritable; the caller re-reads */
    bool ok = platform_private_file_write_at(&file, seed, SIGNER_SEED_BYTES,
                                             0) &&
              platform_private_file_authority_flush(&file);
    if (!ok) {
        (void)platform_private_file_retire(&file, path);
        platform_private_file_close(&file);
        memory_cleanse(seed, SIGNER_SEED_BYTES);
        LOG_FAIL(SIGNER_DOMAIN,
                 "durable write of the signing key failed: path=%s", path);
    }
    platform_private_file_close(&file);
    return true;
}

/* Load this box's seed, creating it on first use when `create` is set. Key
 * creation is announced with a typed line so a new identity never appears
 * silently. Losing the create race to a sibling process is normal and is
 * resolved by reading the winner's key. */
static bool signer_seed_load(uint8_t seed[SIGNER_SEED_BYTES], bool create,
                             bool *present, const char **why)
{
    char path[ZCL_DEV_PROOF_SIGNER_PATH_MAX];
    if (present) *present = false;
    if (!zcl_dev_proof_signer_paths(path, sizeof(path), NULL, 0)) {
        signer_why(why, WHY_UNREADABLE);
        LOG_FAIL(SIGNER_DOMAIN,
                 "cannot resolve the owner-private state root that holds "
                 "%s; set HOME or XDG_STATE_HOME", SIGNER_KEY_LEAF);
    }
    enum signer_seed_state state = signer_seed_read(path, seed);
    if (state == SIGNER_SEED_UNREADABLE) {
        signer_why(why, WHY_UNREADABLE);
        LOG_FAIL(SIGNER_DOMAIN,
                 "signing key must be a private %u-byte regular file: "
                 "path=%s", SIGNER_SEED_BYTES, path);
    }
    if (state == SIGNER_SEED_OK) {
        if (present) *present = true;
        return true;
    }
    if (!create)
        return true; /* absent, and nobody asked for one */
    if (!signer_seed_create(path, seed)) {
        state = signer_seed_read(path, seed);
        if (state != SIGNER_SEED_OK) {
            signer_why(why, WHY_UNREADABLE);
            LOG_FAIL(SIGNER_DOMAIN,
                     "cannot create or read this box's signing key: path=%s",
                     path);
        }
        if (present) *present = true;
        return true;
    }
    uint8_t pubkey[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES];
    uint8_t secret[SIGNER_SEED_BYTES];
    char hex[ZCL_DEV_PROOF_SIGNER_PUBKEY_HEX];
    ed25519_keypair(pubkey, secret, seed);
    memory_cleanse(secret, sizeof(secret));
    zcl_hex_encode(pubkey, sizeof(pubkey), hex);
    LOG_INFO(SIGNER_DOMAIN,
             "signer_key_created pubkey=%s path=%s — copy this key into "
             "%s on any box that must trust this one's push proofs",
             hex, path, SIGNER_ALLOW_LEAF);
    if (present) *present = true;
    return true;
}

static void signer_pubkey_from_seed(
    const uint8_t seed[SIGNER_SEED_BYTES],
    uint8_t pubkey[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES])
{
    uint8_t secret[SIGNER_SEED_BYTES];
    ed25519_keypair(pubkey, secret, seed);
    memory_cleanse(secret, sizeof(secret));
}

bool zcl_dev_proof_signer_public(
    uint8_t pubkey[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES], bool *present,
    const char **why)
{
    uint8_t seed[SIGNER_SEED_BYTES];
    bool have = false;
    signer_why(why, NULL);
    if (!pubkey || !present) {
        signer_why(why, WHY_ARGUMENTS);
        LOG_FAIL(SIGNER_DOMAIN, "public key read needs both outputs");
    }
    memset(pubkey, 0, ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES);
    *present = false;
    if (!signer_seed_load(seed, false, &have, why))
        return false;
    if (have)
        signer_pubkey_from_seed(seed, pubkey);
    memory_cleanse(seed, sizeof(seed));
    *present = have;
    return true;
}

bool zcl_dev_proof_signer_sign(
    const uint8_t *message, size_t message_len,
    uint8_t pubkey[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES],
    uint8_t signature[ZCL_DEV_PROOF_SIGNER_SIGNATURE_BYTES],
    const char **why)
{
    uint8_t seed[SIGNER_SEED_BYTES];
    bool have = false;
    signer_why(why, NULL);
    if ((!message && message_len) || !pubkey || !signature) {
        signer_why(why, WHY_ARGUMENTS);
        LOG_FAIL(SIGNER_DOMAIN, "sign needs a message and both outputs");
    }
    memset(pubkey, 0, ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES);
    memset(signature, 0, ZCL_DEV_PROOF_SIGNER_SIGNATURE_BYTES);
    if (!signer_seed_load(seed, true, &have, why))
        return false;
    if (!have) {
        memory_cleanse(seed, sizeof(seed));
        signer_why(why, WHY_UNREADABLE);
        LOG_FAIL(SIGNER_DOMAIN,
                 "no signing key after create; refusing to seal an "
                 "unsigned receipt");
    }
    signer_pubkey_from_seed(seed, pubkey);
    ed25519_sign(signature, message, message_len, seed, pubkey);
    memory_cleanse(seed, sizeof(seed));
    return true;
}

/* One pass over signers.allow. `target` (when non-NULL) is the key being
 * looked up; `own` (when present) is this box's key, so the same pass can
 * report whether the operator also listed it. */
struct signer_allow_scan {
    bool present;
    uint32_t trusted;
    uint32_t malformed;
    bool self_listed;
    bool found_target;
};

static void signer_allow_line(const char *line,
                              const uint8_t *target,
                              const uint8_t *own, bool own_present,
                              struct signer_allow_scan *scan)
{
    uint8_t key[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES];
    size_t start = 0, end = strlen(line);
    char text[ZCL_DEV_PROOF_SIGNER_PUBKEY_HEX];
    while (start < end && (line[start] == ' ' || line[start] == '\t'))
        start++;
    while (end > start && (line[end - 1] == ' ' || line[end - 1] == '\t' ||
                           line[end - 1] == '\r'))
        end--;
    if (start == end || line[start] == '#')
        return; /* blank and comment lines are neither trusted nor malformed */
    size_t len = end - start;
    if (len + 1u > sizeof(text)) {
        scan->malformed++;
        return;
    }
    memcpy(text, line + start, len);
    text[len] = 0;
    if (!zcl_hex_decode(text, key, sizeof(key))) {
        scan->malformed++;
        return;
    }
    scan->trusted++;
    if (target && memcmp(key, target, sizeof(key)) == 0)
        scan->found_target = true;
    if (own_present && own && memcmp(key, own, sizeof(key)) == 0)
        scan->self_listed = true;
}

static bool signer_allow_scan(const uint8_t *target, const uint8_t *own,
                              bool own_present,
                              struct signer_allow_scan *scan)
{
    char path[ZCL_DEV_PROOF_SIGNER_PATH_MAX];
    struct platform_positioned_file file;
    uint64_t size = 0;
    memset(scan, 0, sizeof(*scan));
    if (!zcl_dev_proof_signer_paths(NULL, 0, path, sizeof(path)))
        return false;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return true; /* no allowlist is a state, not a failure */
    bool sized = platform_positioned_file_size(&file, &size);
    if (!sized || size > SIGNER_ALLOW_MAX_BYTES) {
        platform_positioned_file_close(&file);
        LOG_WARN(SIGNER_DOMAIN,
                 "ignoring %s: it must be readable and at most %u bytes",
                 path, SIGNER_ALLOW_MAX_BYTES);
        return true;
    }
    char *text = zcl_malloc((size_t)size + 1u, "dev-proof-signers-allow");
    if (!text) {
        platform_positioned_file_close(&file);
        LOG_WARN(SIGNER_DOMAIN, "ignoring %s: out of memory", path);
        return true;
    }
    int64_t got = size ? platform_positioned_file_read(&file, text,
                                                       (size_t)size, 0) : 0;
    platform_positioned_file_close(&file);
    if (got < 0 || (uint64_t)got != size) {
        free(text);
        LOG_WARN(SIGNER_DOMAIN, "ignoring %s: short read", path);
        return true;
    }
    text[size] = 0;
    scan->present = true;
    /* Walk to the terminator, not to the last newline: a file whose final
     * line has no newline still has a key on it, and dropping that line
     * would silently un-trust the last box an operator added. */
    size_t begin = 0;
    for (size_t i = 0; i <= (size_t)size; i++) {
        if (i != (size_t)size && text[i] != '\n')
            continue;
        char saved = text[i];
        text[i] = 0;
        signer_allow_line(text + begin, target, own, own_present, scan);
        text[i] = saved;
        begin = i + 1u;
    }
    free(text);
    return true;
}

bool zcl_dev_proof_signer_allowlist_state(
    struct zcl_dev_proof_allowlist_state *out, const char **why)
{
    struct signer_allow_scan scan;
    uint8_t own[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES];
    bool own_present = false;
    signer_why(why, NULL);
    if (!out) {
        signer_why(why, WHY_ARGUMENTS);
        LOG_FAIL(SIGNER_DOMAIN, "allowlist state needs an output");
    }
    memset(out, 0, sizeof(*out));
    if (!zcl_dev_proof_signer_public(own, &own_present, why))
        return false;
    if (!signer_allow_scan(NULL, own, own_present, &scan)) {
        signer_why(why, WHY_UNREADABLE);
        LOG_FAIL(SIGNER_DOMAIN, "cannot resolve the signer state directory");
    }
    out->present = scan.present;
    out->trusted = scan.trusted;
    out->malformed = scan.malformed;
    out->self_listed = scan.self_listed;
    return true;
}

bool zcl_dev_proof_signer_verify(
    const uint8_t *message, size_t message_len,
    const uint8_t pubkey[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES],
    const uint8_t signature[ZCL_DEV_PROOF_SIGNER_SIGNATURE_BYTES],
    const char **why)
{
    uint8_t own[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES];
    bool own_present = false;
    struct signer_allow_scan scan;
    signer_why(why, NULL);
    if ((!message && message_len) || !pubkey || !signature) {
        signer_why(why, WHY_ARGUMENTS);
        LOG_FAIL(SIGNER_DOMAIN, "verify needs a message, a key and a signature");
    }
    if (!zcl_dev_proof_signer_public(own, &own_present, why))
        return false; /* a key file this box cannot read is not a shrug */
    bool trusted = own_present &&
                   memcmp(own, pubkey, sizeof(own)) == 0;
    if (!trusted) {
        if (!signer_allow_scan(pubkey, own, own_present, &scan)) {
            signer_why(why, WHY_UNREADABLE);
            LOG_FAIL(SIGNER_DOMAIN,
                     "cannot resolve the signer state directory");
        }
        trusted = scan.found_target;
    }
    if (!trusted) {
        char hex[ZCL_DEV_PROOF_SIGNER_PUBKEY_HEX];
        zcl_hex_encode(pubkey, ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES, hex);
        signer_why(why, WHY_UNKNOWN);
        LOG_FAIL(SIGNER_DOMAIN,
                 "signer %s is not this box and is not listed in %s; add "
                 "that line to trust it", hex, SIGNER_ALLOW_LEAF);
    }
    if (!ed25519_verify(signature, message, message_len, pubkey)) {
        signer_why(why, WHY_SIGNATURE);
        return false;
    }
    return true;
}
