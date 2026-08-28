/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: pure, independently testable persistent onion identity storage,
 * rotation, and prop224 address derivation. No embedded-Tor state lives here. */

#include "net/tor_integration.h"
#include "crypto/ed25519.h"
#include "crypto/random_secret.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "sha3/sha3.h"
#include "util/log_macros.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static bool onion_identity_read_seed(const char *path, uint8_t seed[32],
                                     struct platform_private_file *retained)
{
    struct platform_private_file file;
    uint64_t size = 0;
    platform_private_file_init(&file);
    if (!platform_private_file_open_locked(path, &file) ||
        !platform_private_file_size(&file, &size) || size != 32 ||
        !platform_private_file_read_at(&file, seed, 32, 0)) {
        platform_private_file_close(&file);
        return false;
    }
    if (retained) {
        *retained = file;
        platform_private_file_init(&file);
    }
    platform_private_file_close(&file);
    return true;
}

static bool onion_identity_publish_hostname(const char *path,
                                            const char *line, size_t size)
{
    uint8_t nonce[16];
    if (!zcl_random_secret_bytes(nonce, sizeof(nonce),
                                 "onion_hostname_staging"))
        return false;
    char staging[1280];
    int n = snprintf(staging, sizeof(staging),
                     "%s.tmp.%02x%02x%02x%02x%02x%02x%02x%02x"
                     "%02x%02x%02x%02x%02x%02x%02x%02x",
                     path, nonce[0], nonce[1], nonce[2], nonce[3], nonce[4],
                     nonce[5], nonce[6], nonce[7], nonce[8], nonce[9],
                     nonce[10], nonce[11], nonce[12], nonce[13], nonce[14],
                     nonce[15]);
    if (n < 0 || (size_t)n >= sizeof(staging))
        return false;
    struct platform_private_file file;
    struct platform_private_file_identity identity;
    platform_private_file_init(&file);
    bool created = platform_private_file_create(staging, &file);
    bool have_identity = created &&
                         platform_private_file_identity(&file, &identity);
    bool ok = have_identity &&
              platform_private_file_write_at(&file, line, size, 0) &&
              platform_private_file_truncate(&file, size) &&
              platform_private_file_flush(&file) &&
              platform_private_file_replace(&file, staging, path);
    if (!ok && have_identity)
        (void)platform_private_file_retire_if_identity(&file, staging,
                                                       &identity);
    platform_private_file_close(&file);
    return ok;
}

static void base32_lower_encode(const uint8_t *data, size_t len, char *out)
{
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyz234567";
    unsigned int buffer = 0;
    int bits = 0;
    char *p = out;
    for (size_t i = 0; i < len; i++) {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            *p++ = alpha[(buffer >> (bits - 5)) & 31u];
            bits -= 5;
        }
    }
    if (bits > 0)
        *p++ = alpha[(buffer << (5 - bits)) & 31u];
    *p = '\0';
}

bool onion_identity_address_from_seed(const uint8_t seed[32],
                                      char *out, size_t out_size)
{
    if (!seed || !out || out_size < 57)
        LOG_FAIL("tor", "onion_identity_address_from_seed: bad args "
                        "(out_size=%zu)", out_size);

    uint8_t pk[32], sk[32];
    ed25519_keypair(pk, sk, seed);

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const char prefix[] = ".onion checksum";
    sha3_256_write(&ctx, (const unsigned char *)prefix, sizeof(prefix) - 1);
    sha3_256_write(&ctx, pk, sizeof(pk));
    const uint8_t version = 3;
    sha3_256_write(&ctx, &version, 1);
    uint8_t digest[SHA3_256_OUTPUT_SIZE];
    sha3_256_finalize(&ctx, digest);

    uint8_t blob[35];
    memcpy(blob, pk, 32);
    blob[32] = digest[0];
    blob[33] = digest[1];
    blob[34] = version;
    base32_lower_encode(blob, sizeof(blob), out);
    return true;
}

static bool onion_identity_dir(const char *datadir, char *dir_out,
                               size_t dir_size)
{
    if (!datadir || !dir_out)
        LOG_FAIL("tor", "onion_identity_dir: missing datadir or dir_out");
    int n = snprintf(dir_out, dir_size, "%s/tor_data/onion_service", datadir);
    if (n < 0 || (size_t)n >= dir_size)
        LOG_FAIL("tor", "onion identity path too long for datadir: %s",
                 datadir);

    char tor_data[1024];
    snprintf(tor_data, sizeof(tor_data), "%s/tor_data", datadir);
    if (!platform_private_directory_ensure(tor_data))
        LOG_FAIL("tor", "private directory %s failed: %s", tor_data,
                 strerror(errno));
    if (!platform_private_directory_ensure(dir_out))
        LOG_FAIL("tor", "private directory %s failed: %s", dir_out,
                 strerror(errno));
    return true;
}

bool onion_identity_ensure(const char *datadir, uint8_t seed_out[32],
                           char *addr_out, size_t addr_out_size,
                           bool *created_out)
{
    if (!datadir || !seed_out)
        LOG_FAIL("tor", "onion_identity_ensure: missing datadir or seed_out");

    char dir[1024];
    if (!onion_identity_dir(datadir, dir, sizeof(dir)))
        return false;

    char seed_path[1152], hostname_path[1152];
    snprintf(seed_path, sizeof(seed_path), "%s/identity_seed", dir);
    snprintf(hostname_path, sizeof(hostname_path), "%s/hostname", dir);

    bool created = false;
    if (!platform_private_path_absent(seed_path)) {
        if (!onion_identity_read_seed(seed_path, seed_out, NULL))
            LOG_FAIL("tor", "onion identity seed corrupt or unsafe (want "
                            "exactly 32 private bytes): %s — refusing to "
                            "silently remint (that "
                            "would change the shop's address); restore the "
                            "file or pass -onion-rotate", seed_path);
    } else {
        if (!zcl_random_secret_bytes(seed_out, 32, "onion_identity_seed"))
            LOG_FAIL("tor", "CSPRNG refused the onion identity seed");
        struct platform_private_file seed_file;
        platform_private_file_init(&seed_file);
        if (!platform_private_file_create(seed_path, &seed_file) ||
            !platform_private_file_write_at(&seed_file, seed_out, 32, 0) ||
            !platform_private_file_truncate(&seed_file, 32) ||
            !platform_private_file_flush(&seed_file)) {
            platform_private_file_close(&seed_file);
            LOG_FAIL("tor", "cannot write onion identity seed %s: %s",
                     seed_path, strerror(errno));
        }
        platform_private_file_close(&seed_file);
        created = true;
    }

    char addr[57];
    if (!onion_identity_address_from_seed(seed_out, addr, sizeof(addr)))
        return false;

    char hline[80];
    int hlen = snprintf(hline, sizeof(hline), "%s.onion\n", addr);
    if (hlen < 0 || (size_t)hlen >= sizeof(hline) ||
        !onion_identity_publish_hostname(hostname_path, hline, (size_t)hlen))
        LOG_FAIL("tor", "cannot atomically write onion hostname file %s",
                 hostname_path);

    if (addr_out) {
        if (addr_out_size < 57)
            LOG_FAIL("tor", "addr_out too small (%zu, want 57)",
                     addr_out_size);
        memcpy(addr_out, addr, 57);
    }
    if (created_out)
        *created_out = created;
    return true;
}

bool onion_identity_rotate(const char *datadir, char *old_addr_out,
                           size_t old_addr_size)
{
    if (!datadir || !old_addr_out || old_addr_size < 57)
        LOG_FAIL("tor", "onion_identity_rotate: bad args");

    char dir[1024];
    if (!onion_identity_dir(datadir, dir, sizeof(dir)))
        return false;

    char seed_path[1152], hostname_path[1152];
    snprintf(seed_path, sizeof(seed_path), "%s/identity_seed", dir);
    snprintf(hostname_path, sizeof(hostname_path), "%s/hostname", dir);

    uint8_t seed[32];
    if (platform_private_path_absent(seed_path)) {
            LOG_WARN("tor", "-onion-rotate: no persistent identity at %s — "
                            "nothing to archive", seed_path);
            return false;
    }
    struct platform_private_file seed_file;
    platform_private_file_init(&seed_file);
    if (!onion_identity_read_seed(seed_path, seed, &seed_file))
        LOG_FAIL("tor", "onion identity seed corrupt or unsafe (want 32): "
                        "%s — refusing to rotate a corrupt identity; restore "
                        "or delete the file deliberately", seed_path);

    char addr[57];
    if (!onion_identity_address_from_seed(seed, addr, sizeof(addr)))
        return false;

    char archive[1280];
    snprintf(archive, sizeof(archive), "%s/archive", dir);
    if (!platform_private_directory_ensure(archive))
        LOG_FAIL("tor", "private directory %s failed: %s", archive,
                 strerror(errno));

    char seed_arch[1408], host_arch[1408];
    snprintf(seed_arch, sizeof(seed_arch), "%s/identity_seed.%s",
             archive, addr);
    snprintf(host_arch, sizeof(host_arch), "%s/hostname.%s", archive, addr);
    struct platform_private_file_identity seed_identity;
    bool already_same = false;
    if (!platform_private_file_identity(&seed_file, &seed_identity) ||
        !platform_private_file_link_no_clobber(seed_path, seed_arch,
                                               &seed_identity,
                                               &already_same) ||
        !platform_private_file_retire_if_identity(&seed_file, seed_path,
                                                  &seed_identity)) {
        platform_private_file_close(&seed_file);
        LOG_FAIL("tor", "failed to archive exact onion identity seed to %s",
                 seed_arch);
    }
    platform_private_file_close(&seed_file);

    if (!platform_private_path_absent(hostname_path)) {
        struct platform_private_file hostname_file;
        struct platform_private_file_identity hostname_identity;
        platform_private_file_init(&hostname_file);
        already_same = false;
        if (!platform_private_file_open_locked(hostname_path, &hostname_file) ||
            !platform_private_file_identity(&hostname_file,
                                             &hostname_identity) ||
            !platform_private_file_link_no_clobber(hostname_path, host_arch,
                                                   &hostname_identity,
                                                   &already_same) ||
            !platform_private_file_retire_if_identity(&hostname_file,
                                                      hostname_path,
                                                      &hostname_identity)) {
            platform_private_file_close(&hostname_file);
            LOG_FAIL("tor", "failed to archive exact onion hostname to %s",
                     host_arch);
        }
        platform_private_file_close(&hostname_file);
    }

    memcpy(old_addr_out, addr, 57);
    return true;
}
