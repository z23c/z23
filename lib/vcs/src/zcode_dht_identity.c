/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Durable local key and delegation files for the ZCODE DHT. */

#include "vcs/zcode_dht_identity.h"

#include "crypto/ed25519.h"
#include "crypto/random_secret.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "support/cleanse.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static _Atomic uint64_t g_dht_identity_temp_sequence;

static bool io_error(char *out, size_t cap, const char *message)
{
    if (out && cap > 0)
        (void)snprintf(out, cap, "%s", message ? message : "identity I/O");
    return false;
}

static bool identity_paths(const char *datadir, char dir[1200],
                           const char *leaf, bool create_dirs,
                           char path[1400],
                           char *err, size_t err_cap)
{
    if (!datadir || !datadir[0] || !leaf)
        return io_error(err, err_cap, "identity datadir is missing");
    char zcode[1150];
    int n = snprintf(zcode, sizeof(zcode), "%s/zcode", datadir);
    if (n <= 0 || (size_t)n >= sizeof(zcode))
        return io_error(err, err_cap, "DHT identity path too long");
    n = snprintf(dir, 1200, "%s/%s", datadir, VCS_ZCODE_DHT_IDENTITY_DIR);
    if (n <= 0 || n >= 1200)
        return io_error(err, err_cap, "DHT identity path too long");
    if (create_dirs &&
        (!platform_private_directory_ensure(zcode) ||
         !platform_private_directory_ensure(dir)))
        return io_error(err, err_cap, "cannot create DHT identity directory");
    n = snprintf(path, 1400, "%s/%s", dir, leaf);
    if (n <= 0 || n >= 1400)
        return io_error(err, err_cap, "DHT identity path too long");
    return true;
}

static bool exact_read_0600(const char *path, uint8_t *out, size_t bytes,
                            char *err, size_t err_cap)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return io_error(err, err_cap, "cannot open DHT identity file");
    if (!platform_positioned_file_snapshot(&file, &before) ||
        before.size != bytes || !platform_positioned_file_is_private(&file)) {
        platform_positioned_file_close(&file);
        return io_error(err, err_cap,
                        "DHT identity file has wrong size or permissions");
    }
    bool ok = platform_positioned_file_read(&file, out, bytes, 0) ==
                  (int64_t)bytes &&
              platform_positioned_file_snapshot(&file, &after) &&
              before.size == after.size && before.volume == after.volume &&
              before.file_low == after.file_low &&
              before.file_high == after.file_high &&
              before.modified_seconds == after.modified_seconds &&
              before.modified_nanoseconds == after.modified_nanoseconds &&
              before.changed_seconds == after.changed_seconds &&
              before.changed_nanoseconds == after.changed_nanoseconds;
    platform_positioned_file_close(&file);
    if (!ok) {
        memory_cleanse(out, bytes);
        return io_error(err, err_cap, "DHT identity read was not exact");
    }
    return true;
}

static bool atomic_write_0600(const char *dir, const char *path,
                              const uint8_t *bytes, size_t len,
                              char *err, size_t err_cap)
{
    uint64_t seq = atomic_fetch_add(&g_dht_identity_temp_sequence, 1);
    char temp[1500];
    int n = snprintf(temp, sizeof(temp), "%s.tmp.%llu.%llu", path,
                     (unsigned long long)os_proc_current_pid(),
                     (unsigned long long)seq);
    if (n <= 0 || (size_t)n >= sizeof(temp))
        return io_error(err, err_cap, "DHT identity temp path too long");
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool ok = platform_private_file_create(temp, &file) &&
              platform_private_file_write_at(&file, bytes, len, 0) &&
              platform_private_file_truncate(&file, len) &&
              platform_private_file_flush(&file) &&
              platform_private_file_replace(&file, temp, path);
    if (!ok) {
        platform_private_file_close(&file);
        (void)platform_private_file_unlink_missing_ok(temp);
        return io_error(err, err_cap, "cannot persist DHT identity temp");
    }
    (void)dir;
    return true;
}

static bool create_0600_no_clobber(const char *dir, const char *path,
                                   const uint8_t *bytes, size_t len,
                                   bool *created, char *err, size_t err_cap)
{
    *created = false;
    uint64_t seq = atomic_fetch_add(&g_dht_identity_temp_sequence, 1);
    char temp[1500];
    int n = snprintf(temp, sizeof(temp), "%s.tmp.%llu.%llu", path,
                     (unsigned long long)os_proc_current_pid(),
                     (unsigned long long)seq);
    struct platform_private_file file;
    struct platform_private_file_identity identity;
    platform_private_file_init(&file);
    bool already_same = false;
    bool ok = n > 0 && (size_t)n < sizeof(temp) &&
              platform_private_file_create(temp, &file) &&
              platform_private_file_write_at(&file, bytes, len, 0) &&
              platform_private_file_truncate(&file, len) &&
              platform_private_file_flush(&file) &&
              platform_private_file_identity(&file, &identity) &&
              platform_private_file_link_no_clobber(
                  temp, path, &identity, &already_same);
    if (ok) {
        *created = !already_same;
        ok = platform_private_parent_flush(dir);
    }
    platform_private_file_close(&file);
    (void)platform_private_file_unlink_missing_ok(temp);
    return ok || io_error(err, err_cap,
                          "cannot exclusively publish DHT identity file");
}

bool vcs_zcode_dht_online_key_load_or_create(
    const char *datadir, uint8_t seed_out[32], uint8_t pubkey_out[32],
    char *err, size_t err_cap)
{
    if (!seed_out || !pubkey_out)
        return io_error(err, err_cap, "online key output is missing");
    memset(seed_out, 0, 32); memset(pubkey_out, 0, 32);
    char dir[1200], path[1400];
    if (!identity_paths(datadir, dir, VCS_ZCODE_DHT_ONLINE_KEY_FILE, true,
                        path, err, err_cap))
        return false;
    if (platform_private_path_absent(path)) {
        uint8_t fresh[32];
        bool created = false;
        if (!zcl_random_secret_bytes(fresh, 32, "zcode_dht_online") ||
            !create_0600_no_clobber(dir, path, fresh, 32, &created,
                                    err, err_cap)) {
            memory_cleanse(fresh, 32); return false;
        }
        if (created)
            memcpy(seed_out, fresh, 32);
        memory_cleanse(fresh, 32);
        if (!created &&
            !exact_read_0600(path, seed_out, 32, err, err_cap))
            return false;
    } else if (!exact_read_0600(path, seed_out, 32, err, err_cap))
        return false;
    uint8_t secret_copy[32];
    zcl_ed25519_keypair(pubkey_out, secret_copy, seed_out);
    memory_cleanse(secret_copy, sizeof(secret_copy));
    return true;
}

bool vcs_zcode_dht_online_key_load(
    const char *datadir, uint8_t seed_out[32], uint8_t pubkey_out[32],
    char *err, size_t err_cap)
{
    if (!seed_out || !pubkey_out)
        return io_error(err, err_cap, "online key output is missing");
    memset(seed_out, 0, 32);
    memset(pubkey_out, 0, 32);
    char dir[1200], path[1400];
    if (!identity_paths(datadir, dir, VCS_ZCODE_DHT_ONLINE_KEY_FILE, false,
                        path, err, err_cap) ||
        !exact_read_0600(path, seed_out, 32, err, err_cap))
        return false;
    uint8_t secret_copy[32];
    zcl_ed25519_keypair(pubkey_out, secret_copy, seed_out);
    memory_cleanse(secret_copy, sizeof(secret_copy));
    return true;
}

bool vcs_zcode_dht_delegation_save(
    const char *datadir, const struct vcs_zcode_dht_delegation *delegation,
    char *err, size_t err_cap)
{
    if (!delegation)
        return io_error(err, err_cap, "delegation is missing");
    uint8_t wire[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
    if (vcs_zcode_dht_delegation_encode(delegation, wire) !=
        VCS_ZCODE_DHT_DELEGATION_OK)
        return io_error(err, err_cap, "delegation does not encode");
    char dir[1200], path[1400];
    if (!identity_paths(datadir, dir, VCS_ZCODE_DHT_DELEGATION_FILE, true,
                        path, err, err_cap))
        return false;
    return atomic_write_0600(dir, path, wire, sizeof(wire), err, err_cap);
}

bool vcs_zcode_dht_delegation_load(
    const char *datadir, struct vcs_zcode_dht_delegation *out,
    char *err, size_t err_cap)
{
    if (!out) return io_error(err, err_cap, "delegation output is missing");
    uint8_t wire[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES];
    char dir[1200], path[1400];
    if (!identity_paths(datadir, dir, VCS_ZCODE_DHT_DELEGATION_FILE, false,
                        path, err, err_cap) ||
        !exact_read_0600(path, wire, sizeof(wire), err, err_cap))
        return false;
    enum vcs_zcode_dht_delegation_error parsed =
        vcs_zcode_dht_delegation_decode(out, wire, sizeof(wire));
    memory_cleanse(wire, sizeof(wire));
    if (parsed != VCS_ZCODE_DHT_DELEGATION_OK)
        return io_error(err, err_cap,
                        vcs_zcode_dht_delegation_error_string(parsed));
    return true;
}
