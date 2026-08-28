/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical persistent Noise X25519 static-key loader. */

#include "net/v2_identity.h"

#include "crypto/curve25519.h"
#include "crypto/random_secret.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "support/cleanse.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static _Atomic uint64_t g_v2_identity_temp_sequence;

static bool identity_error(char *out, size_t cap, const char *what)
{
    if (out && cap > 0)
        (void)snprintf(out, cap, "%s", what ? what : "identity failure");
    return false;
}

static bool identity_read(const char *path, uint8_t private_out[32],
                          uint8_t public_out[32], char *err, size_t err_cap)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false;
    if (!platform_positioned_file_snapshot(&file, &before) ||
        before.size != 32 || !platform_positioned_file_is_private(&file)) {
        platform_positioned_file_close(&file);
        return identity_error(err, err_cap,
                              "v2 identity must be a private 32-byte file");
    }
    bool stable = platform_positioned_file_read(&file, private_out, 32, 0) == 32 &&
                  platform_positioned_file_snapshot(&file, &after) &&
                  before.volume == after.volume &&
                  before.file_low == after.file_low &&
                  before.file_high == after.file_high &&
                  before.size == after.size &&
                  before.modified_seconds == after.modified_seconds &&
                  before.modified_nanoseconds == after.modified_nanoseconds &&
                  before.changed_seconds == after.changed_seconds &&
                  before.changed_nanoseconds == after.changed_nanoseconds;
    platform_positioned_file_close(&file);
    if (!stable) {
        memory_cleanse(private_out, 32);
        return identity_error(err, err_cap, "v2 identity read was not exact");
    }
    if (!curve25519_scalarmult_base(public_out, private_out)) {
        memory_cleanse(private_out, 32);
        return identity_error(err, err_cap, "v2 identity key is invalid");
    }
    return true;
}

static bool identity_write(const char *dir, const char *path,
                           const uint8_t private_key[32], char *err,
                           size_t err_cap)
{
    char temp[1280];
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool created = false;
    for (unsigned int attempt = 0; attempt < 64 && !created; attempt++) {
        uint64_t seq = atomic_fetch_add(&g_v2_identity_temp_sequence, 1);
        int n = snprintf(temp, sizeof(temp), "%s.tmp.%llu", path,
                         (unsigned long long)seq);
        if (n <= 0 || (size_t)n >= sizeof(temp))
            return identity_error(err, err_cap,
                                  "v2 identity temp path too long");
        created = platform_private_file_create(temp, &file);
        if (!created && errno != EEXIST)
            break;
    }
    if (!created)
        return identity_error(err, err_cap, "cannot create v2 identity temp");
    bool ok = platform_private_file_write_at(&file, private_key, 32, 0) &&
              platform_private_file_flush(&file) &&
              platform_private_file_replace(&file, temp, path);
    if (!ok) {
        platform_private_file_close(&file);
        (void)platform_private_file_unlink_missing_ok(temp);
        return identity_error(err, err_cap, "cannot persist v2 identity temp");
    }
    platform_private_file_close(&file);
    if (!platform_private_parent_flush(dir)) {
        return identity_error(err, err_cap,
                              "cannot fsync v2 identity directory");
    }
    return true;
}

bool v2_identity_load_or_create(const char *datadir,
                                uint8_t private_out[32],
                                uint8_t public_out[32],
                                char *err, size_t err_cap)
{
    if (!datadir || !datadir[0] || !private_out || !public_out)
        return identity_error(err, err_cap, "v2 identity argument missing");
    if (err && err_cap > 0)
        err[0] = '\0';
    memset(private_out, 0, 32);
    memset(public_out, 0, 32);
    char path[1152];
    int n = snprintf(path, sizeof(path), "%s/v2_identity.key", datadir);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return identity_error(err, err_cap, "v2 identity path too long");

    if (identity_read(path, private_out, public_out, err, err_cap))
        return true;
    if (!platform_private_path_absent(path)) {
        if (err && err_cap > 0 && err[0])
            return false;
        return identity_error(err, err_cap, "cannot inspect v2 identity");
    }

    uint8_t fresh[32];
    if (!zcl_random_secret_bytes(fresh, sizeof(fresh), "v2_identity") ||
        !curve25519_scalarmult_base(public_out, fresh)) {
        memory_cleanse(fresh, sizeof(fresh));
        return identity_error(err, err_cap, "v2 identity generation failed");
    }
    if (!identity_write(datadir, path, fresh, err, err_cap)) {
        memory_cleanse(fresh, sizeof(fresh));
        memset(public_out, 0, 32);
        return false;
    }
    memcpy(private_out, fresh, 32);
    memory_cleanse(fresh, sizeof(fresh));
    return true;
}
