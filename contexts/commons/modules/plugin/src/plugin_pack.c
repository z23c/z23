/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: publisher side of the plugin store: build the strict manifest,
 * sign it and write the three files plugin_store_install reads. */

#include "plugin_internal.h"
#if defined(_WIN32)
#include "platform/directory_transaction.h"
#include <unistd.h>
#include <io.h>
#include <fcntl.h>
#endif

#include "base/cleanse.h"
#include "base/hex.h"
#include "crypto/ed25519.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

enum { PP_MANIFEST_MAX = 1024, PP_SIG_MAX = 320 };

static bool pp_manifest_build(const struct plugin_pack_request *r,
                              const char *sha, char *out, size_t cap)
{
    int n = snprintf(out, cap,
                     "{\"schema\":\"z23.plugin.v1\",\"name\":\"%s\","
                     "\"version\":\"%s\",\"interface_version\":%d,"
                     "\"sha3_512\":\"%s\",\"capabilities\":[",
                     r->name, r->version, r->interface_version ? r->interface_version : 1,
                     sha);
    bool first = true;
    for (unsigned i = 0; n > 0 && (size_t)n < cap && plugin_capability_name(i); i++) {
        if (!(r->capabilities & (1u << i)))
            continue;
        n += snprintf(out + n, cap - (size_t)n, "%s\"%s\"", first ? "" : ",",
                      plugin_capability_name(i));
        first = false;
    }
    if (n > 0 && (size_t)n < cap)
        n += snprintf(out + n, cap - (size_t)n, "]}\n");
    return n > 0 && (size_t)n < cap;
}

/* Writes data to path through an exclusive sibling file and a rename, so a
 * reader never sees a partial file and a leftover sibling is not reused. */
static bool pp_write_atomic(const char *path, const char *data, size_t len)
{
#if defined(_WIN32)
    return platform_directory_transaction_write_atomic(path, data, len);
#else

    char tmp[PLUGIN_PATH_MAX];
    if (!plugin_join(tmp, sizeof(tmp), path, NULL, NULL, NULL) ||
        strlen(tmp) + 5 >= sizeof(tmp))
        return false;
    strcat(tmp, ".tmp");
    (void)unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0)
        return false;
    bool ok = write(fd, data, len) == (ssize_t)len && fchmod(fd, 0644) == 0 &&
              fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    ok = ok && rename(tmp, path) == 0;
    if (!ok)
        (void)unlink(tmp);
    return ok;

#endif
}

static enum plugin_status pp_sign_doc(const uint8_t seed[PLUGIN_KEY_FILE_BYTES],
                                      const char *manifest, size_t len,
                                      char *out, size_t cap, char *pub_hex)
{
    uint8_t pk[32], sig[64], digest[PLUGIN_DIGEST_BYTES];
    char sig_hex[129];
    plugin_key_public(seed, pk);
    plugin_manifest_digest(manifest, len, digest);
    ed25519_sign(sig, digest, sizeof(digest), seed, pk);
    zcl_hex_encode(pk, sizeof(pk), pub_hex);
    zcl_hex_encode(sig, sizeof(sig), sig_hex);
    int n = snprintf(out, cap,
                     "{\"sig_alg\":\"ed25519\",\"public_key\":\"%s\","
                     "\"signature\":\"%s\"}\n", pub_hex, sig_hex);
    return n > 0 && (size_t)n < cap ? PLUGIN_OK : PLUGIN_ERR_IO;
}

static bool pp_args_valid(const struct plugin_pack_request *r)
{
    return r && r->exe_path && r->key_path && plugin_name_valid(r->name) &&
           plugin_version_valid(r->version) &&
           r->interface_version >= 0 && r->interface_version <= 2;
}

static enum plugin_status pp_out_dir(const char *dir)
{
    struct stat st;
    if (stat(dir, &st) == 0)
        return S_ISDIR(st.st_mode) ? PLUGIN_OK : PLUGIN_ERR_ARGUMENT;
    return errno == ENOENT && plugin_mkdir_new(dir) ? PLUGIN_OK : PLUGIN_ERR_IO;
}

/* Copies the executable beside the manifest, hashing the bytes written. */
static enum plugin_status pp_store_exe(const char *src, const char *dst,
                                       char sha[PLUGIN_HEX_SHA3_512 + 1])
{
#if defined(_WIN32)
    char tmp[PLUGIN_PATH_MAX];
    int n=snprintf(tmp,sizeof(tmp),"%s.copy.%ld",dst,(long)getpid());
    if(n<=0 || (size_t)n>=sizeof(tmp)) return PLUGIN_ERR_ARGUMENT;
    enum plugin_status st=plugin_copy_file(src,tmp,0755,sha);
    if(st==PLUGIN_OK && !platform_directory_transaction_replace_path(tmp,dst))
        st=PLUGIN_ERR_IO;
    return st;
#else

    char tmp[PLUGIN_PATH_MAX];
    if (!plugin_join(tmp, sizeof(tmp), dst, NULL, NULL, NULL) ||
        strlen(tmp) + 5 >= sizeof(tmp))
        return PLUGIN_ERR_ARGUMENT;
    strcat(tmp, ".tmp");
    (void)unlink(tmp);
    enum plugin_status st = plugin_copy_file(src, tmp, 0755, sha);
    if (st == PLUGIN_OK && (chmod(tmp, 0755) != 0 || rename(tmp, dst) != 0))
        st = PLUGIN_ERR_IO;
    if (st != PLUGIN_OK)
        (void)unlink(tmp);
    return st;

#endif
}

static enum plugin_status pp_publish(const struct plugin_pack_request *r,
                                     const uint8_t seed[PLUGIN_KEY_FILE_BYTES],
                                     const char *dir,
                                     struct plugin_pack_result *out)
{
    char exe[PLUGIN_PATH_MAX], sig_path[PLUGIN_PATH_MAX], leaf[PLUGIN_NAME_MAX + 16];
    char manifest[PP_MANIFEST_MAX], sig[PP_SIG_MAX], exe_sha[PLUGIN_HEX_SHA3_512 + 1];
    uint8_t digest[PLUGIN_DIGEST_BYTES];
    struct plugin_manifest check;
    enum plugin_status st = pp_out_dir(dir);
    if (st != PLUGIN_OK)
        return st;
    snprintf(leaf, sizeof(leaf), "%s.plugin.json", r->name);
    bool paths = plugin_join(exe, sizeof(exe), dir, r->name, NULL, NULL) &&
                 plugin_join(out->manifest_path, sizeof(out->manifest_path), dir, leaf, NULL, NULL);
    snprintf(leaf, sizeof(leaf), "%s.plugin.sig", r->name);
    paths = paths && plugin_join(sig_path, sizeof(sig_path), dir, leaf, NULL, NULL);
    if (!paths)
        return PLUGIN_ERR_ARGUMENT;
    st = pp_store_exe(r->exe_path, exe, exe_sha);
    if (st != PLUGIN_OK)
        return st;
    if (!pp_manifest_build(r, exe_sha, manifest, sizeof(manifest)) ||
        plugin_manifest_parse(manifest, strlen(manifest), &check) != PLUGIN_OK)
        return PLUGIN_ERR_MANIFEST_INVALID;
    /* The generation id is the signed manifest digest, as plugin_store derives it. */
    plugin_manifest_digest(manifest, strlen(manifest), digest);
    zcl_hex_encode(digest, sizeof(digest), out->generation);
    st = pp_sign_doc(seed, manifest, strlen(manifest), sig, sizeof(sig), out->public_key);
    if (st == PLUGIN_OK && !(pp_write_atomic(out->manifest_path, manifest, strlen(manifest)) &&
                             pp_write_atomic(sig_path, sig, strlen(sig))))
        st = PLUGIN_ERR_IO;
    return st;
}

enum plugin_status plugin_pack(const struct plugin_pack_request *request,
                               struct plugin_pack_result *result)
{
    uint8_t seed[PLUGIN_KEY_FILE_BYTES];
    if (!pp_args_valid(request) || !result)
        return PLUGIN_ERR_ARGUMENT;
    memset(result, 0, sizeof(*result));
    enum plugin_status st = plugin_key_load(request->key_path, seed);
    if (st != PLUGIN_OK)
        return st;
    st = pp_publish(request, seed, request->out_dir ? request->out_dir : ".", result);
    memory_cleanse(seed, sizeof(seed));
    return st;
}
