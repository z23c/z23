/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: This box's fleet Ed25519 key and the operator key it trusts.
 *          See tools/dev/fleet_enrol.h for the contract.
 *
 * Deliberately the same custody shape as tools/dev/dev_proof_signer.c — one
 * 32-byte seed, mode 0600, under platform_state_root(), created on first use
 * by the producer and announced by a typed log line — and deliberately a
 * DIFFERENT file. A push-proof signer says "this box ran these gates"; a
 * fleet key says "this box is a member of this owner's fleet". Revoking one
 * must not revoke the other, and one file cannot be revoked twice.
 *
 * platform_state_root() is where the Windows/POSIX difference already lives,
 * so nothing in this file needs a _WIN32 branch: it works the same on a
 * native MSYS2 UCRT64 box as on Linux or macOS.
 */

#include "fleet_enrol.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "crypto/ed25519.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "platform/state_root.h"

#include <stdio.h>
#include <string.h>

#define FLEET_DOMAIN "fleet-enrol"
#define FLEET_DIR_LEAF "fleet"
#define FLEET_KEY_LEAF "box.ed25519"
#define FLEET_OPERATOR_LEAF "operator.pub"

static void fe_why(const char **why, const char *token)
{
    if (why) *why = token;
}

bool fleet_enrol_state_path(const char *leaf, char *out, size_t cap)
{
    char root[FLEET_ENROL_PATH_MAX];
    char dir[FLEET_ENROL_PATH_MAX];
    if (!out || !leaf || !platform_state_root(root, sizeof(root)))
        return false;
    int n = snprintf(dir, sizeof(dir), "%s/%s", root, FLEET_DIR_LEAF);
    if (n <= 0 || (size_t)n >= sizeof(dir) ||
        !platform_private_directory_ensure(dir))
        return false;
    n = snprintf(out, cap, "%s/%s", dir, leaf);
    return n > 0 && (size_t)n < cap;
}

/* Read the seed. A path that will not open at all reports ABSENT so a
 * caller that only verifies concludes "no key here" rather than "broken";
 * a file that opens but is not a private 32-byte regular file is the
 * wrong-mode, wrong-size and truncated-write case, and is UNREADABLE. */
enum fe_seed_state { FE_SEED_OK = 0, FE_SEED_ABSENT, FE_SEED_UNREADABLE };

static enum fe_seed_state fe_seed_read(const char *path,
                                       uint8_t seed[FLEET_ENROL_SEED_BYTES])
{
    struct platform_positioned_file file;
    uint64_t size = 0;
    platform_positioned_file_init(&file);
    memset(seed, 0, FLEET_ENROL_SEED_BYTES);
    if (!platform_positioned_file_open(&file, path))
        return FE_SEED_ABSENT;
    bool ok = platform_positioned_file_is_current_user_only(&file) &&
              platform_positioned_file_size(&file, &size) &&
              size == (uint64_t)FLEET_ENROL_SEED_BYTES &&
              platform_positioned_file_read(&file, seed,
                                            FLEET_ENROL_SEED_BYTES, 0) ==
                  (int64_t)FLEET_ENROL_SEED_BYTES;
    platform_positioned_file_close(&file);
    if (ok) return FE_SEED_OK;
    memory_cleanse(seed, FLEET_ENROL_SEED_BYTES);
    return FE_SEED_UNREADABLE;
}

static bool fe_seed_create(const char *path,
                           uint8_t seed[FLEET_ENROL_SEED_BYTES])
{
    struct platform_private_file file;
    platform_private_file_init(&file);
    if (!rng_fill(seed, FLEET_ENROL_SEED_BYTES)) {
        memory_cleanse(seed, FLEET_ENROL_SEED_BYTES);
        LOG_FAIL(FLEET_DOMAIN,
                 "host CSPRNG refused a %d-byte fleet key seed; refusing to "
                 "invent one", FLEET_ENROL_SEED_BYTES);
    }
    if (!platform_private_file_create(path, &file))
        return false; /* already there, or unwritable; the caller re-reads */
    bool ok = platform_private_file_write_at(&file, seed,
                                             FLEET_ENROL_SEED_BYTES, 0) &&
              platform_private_file_authority_flush(&file);
    if (!ok) {
        (void)platform_private_file_retire(&file, path);
        platform_private_file_close(&file);
        memory_cleanse(seed, FLEET_ENROL_SEED_BYTES);
        LOG_FAIL(FLEET_DOMAIN, "durable write of the fleet key failed: path=%s",
                 path);
    }
    platform_private_file_close(&file);
    return true;
}

bool fleet_enrol_key_load(uint8_t seed[FLEET_ENROL_SEED_BYTES],
                          uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES],
                          bool create, bool *present, const char **why)
{
    char path[FLEET_ENROL_PATH_MAX];
    uint8_t secret[FLEET_ENROL_SEED_BYTES];
    char hex[FLEET_ENROL_PUBKEY_HEX];
    fe_why(why, NULL);
    if (present) *present = false;
    memset(pubkey, 0, FLEET_ENROL_PUBKEY_BYTES);
    if (!fleet_enrol_state_path(FLEET_KEY_LEAF, path, sizeof(path))) {
        fe_why(why, FLEET_ENROL_WHY_STATE_ROOT);
        return false;
    }
    enum fe_seed_state state = fe_seed_read(path, seed);
    if (state == FE_SEED_UNREADABLE) {
        fe_why(why, FLEET_ENROL_WHY_KEY_UNWRITABLE);
        LOG_WARN(FLEET_DOMAIN,
                 "the fleet key must be a private %d-byte regular file: "
                 "path=%s", FLEET_ENROL_SEED_BYTES, path);
        return false;
    }
    if (state == FE_SEED_ABSENT) {
        if (!create) return true; /* absent, and nobody asked for one */
        if (!fe_seed_create(path, seed) &&
            fe_seed_read(path, seed) != FE_SEED_OK) {
            /* Losing the create race to a sibling process is normal and is
             * resolved by reading the winner's key; anything else is a real
             * permission problem and is named. */
            fe_why(why, FLEET_ENROL_WHY_KEY_UNWRITABLE);
            LOG_WARN(FLEET_DOMAIN,
                     "cannot create or read this box's fleet key: path=%s",
                     path);
            return false;
        }
        ed25519_keypair(pubkey, secret, seed);
        memory_cleanse(secret, sizeof(secret));
        zcl_hex_encode(pubkey, FLEET_ENROL_PUBKEY_BYTES, hex);
        LOG_INFO(FLEET_DOMAIN,
                 "fleet_key_created pubkey=%s path=%s — this is the identity "
                 "this box enrols and signs invites with", hex, path);
        if (present) *present = true;
        return true;
    }
    ed25519_keypair(pubkey, secret, seed);
    memory_cleanse(secret, sizeof(secret));
    if (present) *present = true;
    return true;
}

bool fleet_enrol_operator_read(uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES],
                               bool *present, const char **why)
{
    struct platform_positioned_file file;
    char path[FLEET_ENROL_PATH_MAX];
    char text[FLEET_ENROL_PUBKEY_HEX];
    uint64_t size = 0;
    fe_why(why, NULL);
    memset(pubkey, 0, FLEET_ENROL_PUBKEY_BYTES);
    if (present) *present = false;
    if (!fleet_enrol_state_path(FLEET_OPERATOR_LEAF, path, sizeof(path))) {
        fe_why(why, FLEET_ENROL_WHY_STATE_ROOT);
        return false;
    }
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return true; /* this box has never joined a fleet */
    bool ok = platform_positioned_file_size(&file, &size) &&
              size == (uint64_t)(FLEET_ENROL_PUBKEY_HEX - 1) &&
              platform_positioned_file_read(&file, text,
                                            FLEET_ENROL_PUBKEY_HEX - 1, 0) ==
                  (int64_t)(FLEET_ENROL_PUBKEY_HEX - 1);
    platform_positioned_file_close(&file);
    text[FLEET_ENROL_PUBKEY_HEX - 1] = '\0';
    if (!ok || !zcl_hex_decode_lower(text, pubkey, FLEET_ENROL_PUBKEY_BYTES)) {
        memset(pubkey, 0, FLEET_ENROL_PUBKEY_BYTES);
        fe_why(why, FLEET_ENROL_WHY_STATE_ROOT);
        LOG_WARN(FLEET_DOMAIN,
                 "the recorded fleet operator key is not 64 lowercase hex "
                 "digits: path=%s", path);
        return false;
    }
    if (present) *present = true;
    return true;
}

bool fleet_enrol_operator_write(
    const uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES], const char **why)
{
    struct platform_private_file file;
    char path[FLEET_ENROL_PATH_MAX];
    char hex[FLEET_ENROL_PUBKEY_HEX];
    fe_why(why, NULL);
    if (!fleet_enrol_state_path(FLEET_OPERATOR_LEAF, path, sizeof(path))) {
        fe_why(why, FLEET_ENROL_WHY_STATE_ROOT);
        return false;
    }
    zcl_hex_encode(pubkey, FLEET_ENROL_PUBKEY_BYTES, hex);
    platform_private_file_init(&file);
    /* Re-joining the same fleet rewrites the same 64 bytes; joining a
     * different one replaces them, which is exactly what pasting a new
     * owner's invite means. The truncate keeps a shorter key from leaving a
     * longer key's tail behind. */
    if (!platform_private_file_open_locked_create(path, &file)) {
        fe_why(why, FLEET_ENROL_WHY_KEY_UNWRITABLE);
        return false;
    }
    bool ok = platform_private_file_truncate(&file, 0) &&
              platform_private_file_write_at(&file, hex,
                                             FLEET_ENROL_PUBKEY_HEX - 1, 0) &&
              platform_private_file_authority_flush(&file);
    platform_private_file_close(&file);
    if (!ok) {
        fe_why(why, FLEET_ENROL_WHY_KEY_UNWRITABLE);
        LOG_WARN(FLEET_DOMAIN, "cannot record the fleet operator key: path=%s",
                 path);
        return false;
    }
    return true;
}
