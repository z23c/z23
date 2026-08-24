/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: pure, independently testable persistent onion identity storage,
 * rotation, and prop224 address derivation. No embedded-Tor state lives here. */

#include "net/tor_integration.h"
#include "crypto/ed25519.h"
#include "crypto/random_secret.h"
#include "sha3/sha3.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
    if (mkdir(tor_data, 0700) != 0 && errno != EEXIST)
        LOG_FAIL("tor", "mkdir %s failed: %s", tor_data, strerror(errno));
    if (mkdir(dir_out, 0700) != 0 && errno != EEXIST)
        LOG_FAIL("tor", "mkdir %s failed: %s", dir_out, strerror(errno));
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
    int fd = open(seed_path, O_RDONLY);
    if (fd >= 0) {
        ssize_t got = read(fd, seed_out, 32);
        close(fd);
        if (got != 32)
            LOG_FAIL("tor", "onion identity seed corrupt (%zd bytes, want "
                            "32): %s — refusing to silently remint (that "
                            "would change the shop's address); restore the "
                            "file or pass -onion-rotate", got, seed_path);
    } else {
        if (errno != ENOENT)
            LOG_FAIL("tor", "cannot open onion identity seed %s: %s",
                     seed_path, strerror(errno));
        if (!zcl_random_secret_bytes(seed_out, 32, "onion_identity_seed"))
            LOG_FAIL("tor", "CSPRNG refused the onion identity seed");
        fd = open(seed_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0)
            LOG_FAIL("tor", "cannot write onion identity seed %s: %s",
                     seed_path, strerror(errno));
        ssize_t put = write(fd, seed_out, 32);
        close(fd);
        if (put != 32)
            LOG_FAIL("tor", "short write on onion identity seed %s",
                     seed_path);
        created = true;
    }

    char addr[57];
    if (!onion_identity_address_from_seed(seed_out, addr, sizeof(addr)))
        return false;

    int hfd = open(hostname_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (hfd < 0)
        LOG_FAIL("tor", "cannot write onion hostname file %s: %s",
                 hostname_path, strerror(errno));
    char hline[80];
    int hlen = snprintf(hline, sizeof(hline), "%s.onion\n", addr);
    ssize_t hput = write(hfd, hline, (size_t)hlen);
    close(hfd);
    if (hput != hlen)
        LOG_FAIL("tor", "short write on onion hostname file %s",
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
    int fd = open(seed_path, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) {
            LOG_WARN("tor", "-onion-rotate: no persistent identity at %s — "
                            "nothing to archive", seed_path);
            return false;
        }
        LOG_FAIL("tor", "cannot open onion identity seed %s: %s",
                 seed_path, strerror(errno));
    }
    ssize_t got = read(fd, seed, sizeof(seed));
    close(fd);
    if (got != (ssize_t)sizeof(seed))
        LOG_FAIL("tor", "onion identity seed corrupt (%zd bytes, want 32): "
                        "%s — refusing to rotate a corrupt identity; restore "
                        "or delete the file deliberately", got, seed_path);

    char addr[57];
    if (!onion_identity_address_from_seed(seed, addr, sizeof(addr)))
        return false;

    char archive[1280];
    snprintf(archive, sizeof(archive), "%s/archive", dir);
    if (mkdir(archive, 0700) != 0 && errno != EEXIST)
        LOG_FAIL("tor", "mkdir %s failed: %s", archive, strerror(errno));

    char seed_arch[1408], host_arch[1408];
    snprintf(seed_arch, sizeof(seed_arch), "%s/identity_seed.%s",
             archive, addr);
    snprintf(host_arch, sizeof(host_arch), "%s/hostname.%s", archive, addr);
    if (rename(seed_path, seed_arch) != 0)
        LOG_FAIL("tor", "failed to archive onion identity seed to %s: %s",
                 seed_arch, strerror(errno));
    if (rename(hostname_path, host_arch) != 0 && errno != ENOENT)
        LOG_FAIL("tor", "failed to archive onion hostname to %s: %s",
                 host_arch, strerror(errno));

    memcpy(old_addr_out, addr, 57);
    return true;
}
