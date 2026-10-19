/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: strict plugin manifest and signature parsing, key lookup and
 * signature verification. */

#include "plugin_internal.h"

#include "base/hex.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define PM_SIG_DOMAIN "z23.plugin.manifest.v1"
#define PM_SCHEMA "z23.plugin.v1"

static const char *const pm_capabilities[] = {
    "fs.read", "fs.write", "net.client", "net.server",
    "process.spawn", "clock", "ui.panel"
};
enum { PM_CAPABILITY_COUNT = sizeof(pm_capabilities) / sizeof(pm_capabilities[0]) };

static const char *const pm_manifest_keys[] = {
    "schema", "name", "version", "interface_version", "sha3_512",
    "capabilities"
};
static const char *const pm_sig_keys[] = { "sig_alg", "public_key", "signature" };

static const struct {
    const char *code;
    const char *next_action;
} pm_status_text[] = {
    [PLUGIN_OK] = { "PLUGIN_OK", "" },
    [PLUGIN_ERR_ARGUMENT] = { "PLUGIN_ARGUMENT",
        "pass the documented arguments: z23 discover describe plugin" },
    [PLUGIN_ERR_NO_KEYS] = { "PLUGIN_NO_KEYS",
        "add the publisher key: z23 plugin publisher <64-character-public-key>; "
        "then retry the requested operation" },
    [PLUGIN_ERR_KEYS_MALFORMED] = { "PLUGIN_KEYS_MALFORMED",
        "fix ~/.z23/plugins/publisher_keys so every line is a 64 character public key hex" },
    [PLUGIN_ERR_MANIFEST_MISSING] = { "PLUGIN_MANIFEST_MISSING",
        "pass the path of an existing NAME.plugin.json" },
    [PLUGIN_ERR_MANIFEST_INVALID] = { "PLUGIN_MANIFEST_INVALID",
        "regenerate NAME.plugin.json to match schema z23.plugin.v1 and sign it again" },
    [PLUGIN_ERR_MANIFEST_DUPLICATE_KEY] = { "PLUGIN_MANIFEST_DUPLICATE_KEY",
        "remove the repeated key from the manifest and sign it again" },
    [PLUGIN_ERR_MANIFEST_UNKNOWN_KEY] = { "PLUGIN_MANIFEST_UNKNOWN_KEY",
        "remove the unrecognised key from the manifest and sign it again" },
    [PLUGIN_ERR_SIG_MISSING] = { "PLUGIN_SIG_MISSING",
        "place the detached NAME.plugin.sig next to NAME.plugin.json" },
    [PLUGIN_ERR_SIG_INVALID] = { "PLUGIN_SIG_INVALID",
        "regenerate NAME.plugin.sig with sig_alg, public_key and signature only" },
    [PLUGIN_ERR_SIG_ALG] = { "PLUGIN_SIG_ALG",
        "sign the manifest with ed25519 and set sig_alg to ed25519" },
    [PLUGIN_ERR_KEY_UNKNOWN] = { "PLUGIN_KEY_UNKNOWN",
        "add the publisher key to ~/.z23/plugins/publisher_keys only after you have verified who publishes it" },
    [PLUGIN_ERR_SIG_BAD] = { "PLUGIN_SIG_BAD",
        "obtain an unmodified manifest and signature from the publisher" },
    [PLUGIN_ERR_EXE_MISSING] = { "PLUGIN_EXE_MISSING",
        "place the executable named in the manifest next to NAME.plugin.json" },
    [PLUGIN_ERR_EXE_HASH] = { "PLUGIN_EXE_HASH",
        "obtain an unmodified executable matching the signed sha3_512" },
    [PLUGIN_ERR_NOT_INSTALLED] = { "PLUGIN_NOT_INSTALLED",
        "install it first: z23 plugin install <path to NAME.plugin.json>" },
    [PLUGIN_ERR_NO_GENERATION] = { "PLUGIN_NO_GENERATION",
        "choose a generation shown by: z23 plugin list" },
    [PLUGIN_ERR_NO_LAST_GOOD] = { "PLUGIN_NO_LAST_GOOD",
        "switch to a generation first; rollback needs a recorded last-good" },
    [PLUGIN_ERR_IO] = { "PLUGIN_IO",
        "check permissions and free space under ~/.z23/plugins and retry" },
    [PLUGIN_ERR_KEYS_INSECURE] = { "PLUGIN_KEYS_INSECURE",
        "make publisher_keys and the plugin store regular files and real directories owned by you and not writable by group or others, with no symbolic links inside; then retry" },
    [PLUGIN_ERR_KEY_MISSING] = { "PLUGIN_KEY_MISSING",
        "create the signing key first: z23 plugin keygen <key file>" },
    [PLUGIN_ERR_KEY_INSECURE] = { "PLUGIN_KEY_INSECURE",
#if defined(_WIN32)
        "use a regular signing key in an owner-private directory; its protected ACL and the directory ACL must grant full access only to your account and SYSTEM, with no reparse points" },
#else
        "make the key file a regular file owned by you with mode 0600 (chmod 600 <key file>), not a symbolic link" },
#endif
    [PLUGIN_ERR_KEY_MALFORMED] = { "PLUGIN_KEY_MALFORMED",
        "use a key file of exactly 32 bytes, as written by: z23 plugin keygen <key file>" },
    [PLUGIN_ERR_KEY_EXISTS] = { "PLUGIN_KEY_EXISTS",
        "keygen never overwrites; choose a new key file path" },
    [PLUGIN_ERR_INTERFACE] = { "PLUGIN_INTERFACE",
        "use plugin run for interface 1 and plugin call for interface 2" },
    [PLUGIN_ERR_BUSY] = { "PLUGIN_BUSY",
        "another plugin install, switch or rollback is running for this plugin; wait for it to finish and retry" }
};

const char *plugin_status_code(enum plugin_status status)
{
    size_t n = sizeof(pm_status_text) / sizeof(pm_status_text[0]);
    return (size_t)status < n ? pm_status_text[status].code : "PLUGIN_UNKNOWN";
}

const char *plugin_status_next_action(enum plugin_status status)
{
    size_t n = sizeof(pm_status_text) / sizeof(pm_status_text[0]);
    return (size_t)status < n ? pm_status_text[status].next_action : "";
}

const char *plugin_capability_name(unsigned index)
{
    return index < PM_CAPABILITY_COUNT ? pm_capabilities[index] : NULL;
}

bool plugin_capability_add(const char *name, size_t len, unsigned *mask)
{
    for (unsigned bit = 0; bit < PM_CAPABILITY_COUNT; bit++) {
        if (strlen(pm_capabilities[bit]) != len ||
            strncmp(pm_capabilities[bit], name, len) != 0)
            continue;
        if (*mask & (1u << bit))
            return false;
        *mask |= 1u << bit;
        return true;
    }
    return false;
}

bool plugin_name_valid(const char *name)
{
    size_t len = name ? strlen(name) : 0;
    if (len < 1 || len > PLUGIN_NAME_MAX)
        return false;
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return false;
    }
    return true;
}

bool plugin_hex_valid(const char *hex, size_t len)
{
    uint8_t scratch[PLUGIN_DIGEST_BYTES];
    return len % 2 == 0 && len / 2 <= sizeof(scratch) &&
           zcl_hex_decode_lower(hex, scratch, len / 2);
}

/* Reports the first repeated or unrecognised key of a JSON object. */
static enum plugin_status pm_check_keys(const struct json_value *obj,
                                        const char *const *allowed, size_t n,
                                        enum plugin_status invalid)
{
    if (obj->type != JSON_OBJ)
        return invalid;
    for (size_t i = 0; i < obj->num_children; i++) {
        const char *key = obj->keys[i];
        for (size_t j = 0; j < i; j++)
            if (strcmp(obj->keys[j], key) == 0)
                return invalid == PLUGIN_ERR_MANIFEST_INVALID
                           ? PLUGIN_ERR_MANIFEST_DUPLICATE_KEY : invalid;
        bool known = false;
        for (size_t k = 0; k < n && !known; k++)
            known = strcmp(allowed[k], key) == 0;
        if (!known)
            return invalid == PLUGIN_ERR_MANIFEST_INVALID
                       ? PLUGIN_ERR_MANIFEST_UNKNOWN_KEY : invalid;
    }
    return PLUGIN_OK;
}

static const char *pm_string(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

bool plugin_version_valid(const char *v)
{
    size_t len = v ? strlen(v) : 0;
    if (len < 1 || len > PLUGIN_VERSION_MAX)
        return false;
    for (size_t i = 0; i < len; i++) {
        char c = v[i];
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                  (c >= 'A' && c <= 'Z') || c == '.' || c == '-' || c == '+';
        if (!ok)
            return false;
    }
    return true;
}

static bool pm_capabilities_read(const struct json_value *arr, unsigned *mask)
{
    if (!arr || arr->type != JSON_ARR)
        return false;
    *mask = 0;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *item = json_at(arr, i);
        const char *s = item && item->type == JSON_STR ? json_get_str(item) : NULL;
        unsigned bit = 0;
        while (s && bit < PM_CAPABILITY_COUNT && strcmp(s, pm_capabilities[bit]) != 0)
            bit++;
        if (!s || bit == PM_CAPABILITY_COUNT || (*mask & (1u << bit)))
            return false;
        *mask |= 1u << bit;
    }
    return true;
}

static bool pm_fields_read(const struct json_value *root,
                           struct plugin_manifest *out)
{
    const char *schema = pm_string(root, "schema");
    const char *name = pm_string(root, "name");
    const char *version = pm_string(root, "version");
    const char *sha = pm_string(root, "sha3_512");
    const struct json_value *iv = json_get(root, "interface_version");
    if (!schema || strcmp(schema, PM_SCHEMA) != 0 || !plugin_name_valid(name) ||
        !plugin_version_valid(version) ||
        !plugin_hex_valid(sha, PLUGIN_HEX_SHA3_512) ||
        !iv || iv->type != JSON_INT || json_get_int(iv) < 1 ||
        json_get_int(iv) > 2)
        return false;
    if (!pm_capabilities_read(json_get(root, "capabilities"), &out->capabilities))
        return false;
    snprintf(out->name, sizeof(out->name), "%s", name);
    snprintf(out->version, sizeof(out->version), "%s", version);
    snprintf(out->exe_sha3, sizeof(out->exe_sha3), "%s", sha);
    out->interface_version = json_get_int(iv);
    return true;
}

enum plugin_status plugin_manifest_parse(const char *bytes, size_t len,
                                         struct plugin_manifest *out)
{
    struct json_value root;
    json_init(&root);
    if (!bytes || !out || !json_read(&root, bytes, len)) {
        json_free(&root);
        return PLUGIN_ERR_MANIFEST_INVALID;
    }
    enum plugin_status st = pm_check_keys(
        &root, pm_manifest_keys,
        sizeof(pm_manifest_keys) / sizeof(pm_manifest_keys[0]),
        PLUGIN_ERR_MANIFEST_INVALID);
    memset(out, 0, sizeof(*out));
    if (st == PLUGIN_OK && !pm_fields_read(&root, out))
        st = PLUGIN_ERR_MANIFEST_INVALID;
    json_free(&root);
    return st;
}

static enum plugin_status pm_sig_parse(const char *bytes, size_t len,
                                       uint8_t pk[32], uint8_t sig[64])
{
    struct json_value root;
    json_init(&root);
    enum plugin_status st = PLUGIN_ERR_SIG_INVALID;
    if (bytes && json_read(&root, bytes, len) &&
        pm_check_keys(&root, pm_sig_keys, 3, PLUGIN_ERR_SIG_INVALID) == PLUGIN_OK) {
        const char *alg = pm_string(&root, "sig_alg");
        const char *pub = pm_string(&root, "public_key");
        const char *sg = pm_string(&root, "signature");
        if (alg && strcmp(alg, "ed25519") != 0)
            st = PLUGIN_ERR_SIG_ALG;
        else if (alg && zcl_hex_decode(pub, pk, 32) &&
                 zcl_hex_decode(sg, sig, 64))
            st = PLUGIN_OK;
    }
    json_free(&root);
    return st;
}

/* One publisher key per line. The scan reads the bytes it is given, so the
 * caller decides which snapshot of the key list a verification runs under. */
static enum plugin_status pm_keys_scan(const char *bytes, size_t len, const uint8_t pk[32])
{
    char line[256];
    bool any = false, found = false;
    size_t pos = 0;
    while (pos < len) {
        size_t end = pos;
        while (end < len && bytes[end] != '\n')
            end++;
        size_t n = end - pos;
        while (n > 0 && bytes[pos + n - 1] == '\r')
            n--;
        if (n >= sizeof(line))
            return PLUGIN_ERR_KEYS_MALFORMED;
        memcpy(line, bytes + pos, n);
        line[n] = '\0';
        pos = end + 1;
        if (n == 0)
            continue;
        uint8_t key[32];
        if (!zcl_hex_decode(line, key, 32))
            return PLUGIN_ERR_KEYS_MALFORMED;
        any = true;
        found = found || memcmp(key, pk, 32) == 0;
    }
    if (!any)
        return PLUGIN_ERR_NO_KEYS;
    return found ? PLUGIN_OK : PLUGIN_ERR_KEY_UNKNOWN;
}

void plugin_manifest_digest(const char *manifest, size_t len,
                               uint8_t digest[PLUGIN_DIGEST_BYTES])
{
    static const unsigned char domain[] = PM_SIG_DOMAIN;
    struct sha3_512_ctx ctx;
    sha3_512_init(&ctx);
    sha3_512_write(&ctx, domain, sizeof(domain)); /* includes the NUL */
    sha3_512_write(&ctx, (const unsigned char *)manifest, len);
    sha3_512_finalize(&ctx, digest);
}

enum plugin_status plugin_verify_manifest_keys(const char *manifest, size_t manifest_len,
                                                const char *sig, size_t sig_len,
                                                const char *keys, size_t keys_len,
                                                struct plugin_manifest *out)
{
    uint8_t pk[32], sg[64], digest[PLUGIN_DIGEST_BYTES];
    enum plugin_status st = plugin_manifest_parse(manifest, manifest_len, out);
    if (st == PLUGIN_OK)
        st = pm_sig_parse(sig, sig_len, pk, sg);
    if (st == PLUGIN_OK)
        st = pm_keys_scan(keys, keys_len, pk);
    if (st != PLUGIN_OK)
        return st;
    plugin_manifest_digest(manifest, manifest_len, digest);
    if (!ed25519_verify(sg, digest, sizeof(digest), pk))
        return PLUGIN_ERR_SIG_BAD;
    /* The signed digest covers the capabilities and the executable hash, so it
     * names the grant, not just the bytes. */
    zcl_hex_encode(digest, sizeof(digest), out->generation);
    return PLUGIN_OK;
}

enum plugin_status plugin_verify_manifest(const char *manifest, size_t manifest_len,
                                          const char *sig, size_t sig_len,
                                          const char *keys_path,
                                          struct plugin_manifest *out)
{
    char *keys = NULL;
    size_t keys_len = 0;
    enum plugin_status st = plugin_keys_load(keys_path, &keys, &keys_len);
    if (st != PLUGIN_OK)
        return st;
    st = plugin_verify_manifest_keys(manifest, manifest_len, sig, sig_len, keys,
                                      keys_len, out);
    free(keys);
    return st;
}
