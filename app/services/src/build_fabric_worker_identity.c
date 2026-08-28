/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Persistent private identity and capability declaration for ZBuild workers. */

#include "services/build_fabric_worker.h"

#include "base/hex.h"
#include "crypto/ed25519.h"
#include "crypto/random_secret.h"
#include "crypto/sha3.h"
#include "vcs/build_action.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BFW_IDENTITY_PATH_MAX 4096

struct zcl_result build_fabric_worker_identity_load(
    const char *datadir, struct db_build_worker *worker,
    uint8_t signer_secret[32], uint8_t signer_pubkey[32])
{
    if (!datadir || !datadir[0] || !worker || !signer_secret ||
        !signer_pubkey)
        return ZCL_ERR(-1, "worker identity requires datadir and outputs");
    char zcode[BFW_IDENTITY_PATH_MAX];
    char path[BFW_IDENTITY_PATH_MAX];
    int n = snprintf(zcode, sizeof(zcode), "%s/zcode", datadir);
    if (n <= 0 || (size_t)n >= sizeof(zcode))
        return ZCL_ERR(-1, "worker key path too long");
    if (mkdir(zcode, 0700) != 0 && errno != EEXIST)
        return ZCL_ERR(-1, "mkdir %s: %s", zcode, strerror(errno));
    n = snprintf(path, sizeof(path), "%s/build-worker.ed25519", zcode);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return ZCL_ERR(-1, "worker key path too long");
    uint8_t seed[32];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) {
        if (!zcl_random_secret_bytes(seed, sizeof(seed), "zbuild_worker_key"))
            return ZCL_ERR(-1, "worker key CSPRNG failed");
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0)
            return ZCL_ERR(-1, "create worker key: %s", strerror(errno));
        ssize_t wrote = write(fd, seed, sizeof(seed));
        bool synced = wrote == (ssize_t)sizeof(seed) && fsync(fd) == 0;
        bool ok = close(fd) == 0 && synced;
        if (!ok) {
            (void)unlink(path);
            memset(seed, 0, sizeof(seed));
            return ZCL_ERR(-1, "durable worker key write failed");
        }
        fd = open(path, O_RDONLY | O_CLOEXEC);
    }
    if (fd < 0)
        return ZCL_ERR(-1, "open worker key: %s", strerror(errno));
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (st.st_mode & 077) != 0 || st.st_size != (off_t)sizeof(seed)) {
        close(fd);
        return ZCL_ERR(-1, "worker key must be a private 32-byte regular file");
    }
    size_t off = 0;
    while (off < sizeof(seed)) {
        ssize_t got = read(fd, seed + off, sizeof(seed) - off);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        off += (size_t)got;
    }
    close(fd);
    if (off != sizeof(seed)) {
        memset(seed, 0, sizeof(seed));
        return ZCL_ERR(-1, "worker key read was truncated");
    }
    ed25519_keypair(signer_pubkey, signer_secret, seed);
    memset(seed, 0, sizeof(seed));
    static const char domain[] = "zcl.build_worker.v1";
    struct sha3_256_ctx sha;
    uint8_t worker_id[32];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, signer_pubkey, 32);
    sha3_256_finalize(&sha, worker_id);
    memset(worker, 0, sizeof(*worker));
    zcl_hex_encode(worker_id, sizeof(worker_id), worker->worker_id);
    zcl_hex_encode(signer_pubkey, 32, worker->signer_pubkey);
    (void)snprintf(worker->capabilities, sizeof(worker->capabilities),
                   "linux,x86-64-v3,gcc,%s,%s,%s,%s",
                   VCS_BUILD_ACTION_KIND_V1, VCS_BUILD_ACTION_KIND_TEST_V1,
                   VCS_BUILD_ACTION_KIND_FUZZ_V1,
                   VCS_BUILD_ACTION_KIND_PACKAGE_V1);
    return ZCL_OK;
}
