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

/* Host platform token for the advertised capability string, derived from
 * the compiler's own view of the host — the same __linux__/__APPLE__ split
 * lib/platform/src/os_proc.c already branches on, mirroring the Makefile's
 * ZCL_HOST_OS Darwin/Linux distinction. Not a new seam: reusing the one
 * this codebase already uses for every other Linux/Darwin behavioral fork. */
#if defined(__linux__)
#define BFW_HOST_PLATFORM "linux"
#elif defined(__APPLE__)
#define BFW_HOST_PLATFORM "macos"
#else
#define BFW_HOST_PLATFORM "unknown"
#endif

/* Build the advertised capability string for a host that can actually
 * capture a toolchain capsule, or the named refusal for one that cannot.
 * vcs_toolchain_capsule_v1_capture_gcc() probes crt1.o/crti.o/crtn.o and
 * libc.so.6 (ELF/glibc-specific) and is the exact gate
 * build_fabric_worker_execute() rechecks before running any dispatched
 * c23.compile/.test/.fuzz/.package action; a worker that fails this probe
 * can never execute what those tokens would claim, so it must not
 * advertise them on its durable, signed identity row. */
static struct zcl_result build_fabric_worker_capabilities(
    bool have_toolchain, char *out, size_t out_len)
{
    if (!have_toolchain)
        return ZCL_ERR(-1,
                       "build worker declines: host platform \"%s\" cannot "
                       "capture a %s gcc toolchain capsule "
                       "(vcs_toolchain_capsule_v1_capture_gcc failed "
                       "probing crt1.o/crti.o/crtn.o/libc.so.6); refusing "
                       "to advertise c23.compile/.test/.fuzz/.package "
                       "capability it cannot execute",
                       BFW_HOST_PLATFORM, VCS_BUILD_TARGET_V1);
    int n = snprintf(out, out_len, "%s,x86-64-v3,gcc,%s,%s,%s,%s",
                     BFW_HOST_PLATFORM, VCS_BUILD_ACTION_KIND_V1,
                     VCS_BUILD_ACTION_KIND_TEST_V1,
                     VCS_BUILD_ACTION_KIND_FUZZ_V1,
                     VCS_BUILD_ACTION_KIND_PACKAGE_V1);
    if (n <= 0 || (size_t)n >= out_len)
        return ZCL_ERR(-1, "worker capabilities string too long");
    return ZCL_OK;
}

#ifdef ZCL_TESTING
struct zcl_result build_fabric_worker_capabilities_for_test(
    bool have_toolchain, char *out, size_t out_len)
{
    return build_fabric_worker_capabilities(have_toolchain, out, out_len);
}
#endif

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
    struct vcs_toolchain_capsule_v1 capsule;
    bool have_toolchain = vcs_toolchain_capsule_v1_capture_gcc(&capsule);
    return build_fabric_worker_capabilities(
        have_toolchain, worker->capabilities, sizeof(worker->capabilities));
}
