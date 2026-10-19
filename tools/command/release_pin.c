/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: owner-key pin set, shared release gate and .zid file reader.
 *          See release_pin.h.
 */

#include "command/release_pin.h"

#include "command/native_command.h"
#include "command/native_slot_common.h"

#include "base/hex.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "zid/zid.h"

#include <stdio.h>
#include <string.h>

void release_pin_fingerprint(const uint8_t pubkey[32],
                             char out[RELEASE_PIN_FINGERPRINT_HEX + 1])
{
    struct sha256_ctx ctx;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_init(&ctx);
    sha256_write(&ctx, pubkey, 32);
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, RELEASE_PIN_FINGERPRINT_HEX / 2u, out);
}

bool release_pin_contains(const struct release_pin_set *set,
                          const uint8_t pubkey[32])
{
    for (size_t i = 0; set && i < set->count; i++)
        if (memcmp(set->keys[i], pubkey, 32) == 0)
            return true;
    return false;
}

static bool rp_add(struct release_pin_set *set, const char *hex,
                   struct zcl_command_reply *reply, const char *command)
{
    uint8_t key[32];
    if (!zcl_hex_decode(hex, key, sizeof(key))) {
        zcl_native_refuse(reply, "BAD_PIN", "normalize",
                "a pin is an owner's Ed25519 public key: exactly 64 hex "
                "characters", command);
        return false;
    }
    if (release_pin_contains(set, key))
        return true;
    if (set->count >= RELEASE_PIN_MAX) {
        zcl_native_refuse(reply, "TOO_MANY_PINS", "normalize",
                "the pin set holds at most 256 distinct owner keys", command);
        return false;
    }
    memcpy(set->keys[set->count++], key, sizeof(key));
    return true;
}

/* Trim ASCII whitespace from both ends of a line in place. */
static char *rp_trim(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r')
        s++;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' ||
                     s[n - 1] == '\r' || s[n - 1] == '\n'))
        s[--n] = '\0';
    return s;
}

static bool rp_pin_line(struct release_pin_set *set, char *line, size_t lineno,
                        struct zcl_command_reply *reply, const char *path)
{
    char *key = rp_trim(line);
    if (key[0] == '\0' || key[0] == '#')
        return true;
    uint8_t probe[32];
    if (!zcl_hex_decode(key, probe, sizeof(probe))) {
        char where[64];
        snprintf(where, sizeof(where), "line %zu", lineno);
        zcl_native_refuse(reply, "PIN_FILE_INVALID", "normalize",
                "every non-comment line of a pin file must be one 64-hex "
                "owner public key", where);
        return false;
    }
    return rp_add(set, key, reply, path);
}

static bool rp_load_file(struct release_pin_set *set, const char *path,
                         struct zcl_command_reply *reply)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        zcl_native_refuse(reply, "PIN_FILE_UNREADABLE", "normalize",
                "cannot open the owner-pins file; it must be a local file "
                "listing one 64-hex owner public key per line", path);
        return false;
    }
    char line[256];
    size_t lineno = 0, total = 0, before = set->count;
    bool ok = true;
    while (ok && fgets(line, sizeof(line), fp)) {
        total += strlen(line);
        lineno++;
        if (total > RELEASE_PIN_FILE_MAX_BYTES ||
            (!strchr(line, '\n') && !feof(fp))) {
            zcl_native_refuse(reply, "PIN_FILE_INVALID", "normalize",
                    "pin file lines must be short and the file at most "
                    "64 KiB", path);
            ok = false;
            break;
        }
        ok = rp_pin_line(set, line, lineno, reply, path);
    }
    fclose(fp);
    if (ok && set->count == before) {
        zcl_native_refuse(reply, "PIN_FILE_EMPTY", "normalize",
                "the owner-pins file lists no keys, so nothing could ever "
                "be trusted from it; add the owner's 64-hex public key",
                path);
        ok = false;
    }
    return ok;
}

bool release_pin_collect(const struct json_value *in,
                         struct release_pin_set *set,
                         struct zcl_command_reply *reply, const char *command)
{
    memset(set, 0, sizeof(*set));
    const struct json_value *pin = json_get(in, "pin");
    const struct json_value *file = json_get(in, "pin_file");
    const char *pin_s = pin ? json_get_str(pin) : NULL;
    const char *file_s = file ? json_get_str(file) : NULL;
    if ((pin && !pin_s) || (file && !file_s)) {
        zcl_native_refuse(reply, "BAD_PIN", "normalize",
                "pin and pin_file must be strings", command);
        return false;
    }
    if (pin_s) {
        set->given = true;
        if (!rp_add(set, pin_s, reply, command))
            return false;
    }
    if (file_s) {
        set->given = true;
        if (!rp_load_file(set, file_s, reply))
            return false;
    }
    return true;
}

static bool rp_unpinned(struct zcl_command_reply *reply,
                        const uint8_t signer[32])
{
    char fp[RELEASE_PIN_FINGERPRINT_HEX + 1], hex[65], msg[320];
    release_pin_fingerprint(signer, fp);
    zcl_hex_encode(signer, 32, hex);
    snprintf(msg, sizeof(msg),
             "this release is signed by owner key %s, which is not in your "
             "pins; if you have confirmed that key out of band, add its "
             "64-hex public key to your owner-pins file and retry",
             fp);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, "RELEASE_UNPINNED",
                           "execute", false, false, msg, hex);
    return false;
}

static bool rp_root_check(const struct json_value *in,
                          const uint8_t manifest_root[32],
                          struct zcl_command_reply *reply, const char *command)
{
    const struct json_value *v = json_get(in, "package_root");
    if (!v)
        return true;
    const char *hex = json_get_str(v);
    uint8_t want[32];
    char err[128];
    if (!zcl_native_require_hex64("package_root", hex, want, err,
                                  sizeof(err))) {
        zcl_native_refuse(reply, "BAD_ROOT", "normalize", err, command);
        return false;
    }
    if (memcmp(want, manifest_root, 32) == 0)
        return true;
    char got[65];
    zcl_hex_encode(manifest_root, 32, got);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, "RELEASE_ROOT_MISMATCH",
                           "execute", false, false,
                           "the package root you expect is not the root this "
                           "signed release commits to; these are not the "
                           "bytes the owner released",
                           got);
    return false;
}

bool release_pin_gate(const struct json_value *in, bool require_pin,
                      const uint8_t signer[32], const uint8_t manifest_root[32],
                      struct zcl_command_reply *reply, const char *command)
{
    struct release_pin_set set;
    if (!release_pin_collect(in, &set, reply, command))
        return false;
    if (require_pin && !set.given) {
        zcl_native_refuse(reply, "PIN_REQUIRED", "normalize",
                "installing needs an owner pin: pass pin=<64-hex owner "
                "public key> or pin_file=<local owner-pins file>; there is "
                "no unpinned install", command);
        return false;
    }
    if (set.given && !release_pin_contains(&set, signer))
        return rp_unpinned(reply, signer);
    return rp_root_check(in, manifest_root, reply, command);
}

bool release_pin_read_doc(const char *path, struct zid_doc *doc,
                          const char **code)
{
    char hex[ZID_DOC_MAX * 2 + 2];
    uint8_t wire[ZID_DOC_MAX];
    FILE *fp = path ? fopen(path, "rb") : NULL;
    size_t n = fp ? fread(hex, 1, sizeof(hex) - 1u, fp) : 0;
    bool oversize = fp && !feof(fp);
    if (fp)
        fclose(fp);
    *code = "DOC_UNREADABLE";
    if (!fp || n == 0 || oversize)
        return false;
    while (n > 0 && (hex[n - 1] == '\n' || hex[n - 1] == '\r' ||
                     hex[n - 1] == ' '))
        n--;
    hex[n] = '\0';
    *code = "BAD_DOC_HEX";
    if (n == 0 || (n & 1u) || !zcl_hex_decode(hex, wire, n / 2u))
        return false;
    *code = "DOC_DECODE_FAILED";
    return zid_doc_decode(doc, wire, n / 2u);
}
