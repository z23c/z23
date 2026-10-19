/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: offline receiver-owned pairing model acceptance, no channel runtime. */
#include "test/test_core.h"
#include "models/device_pairing.h"
#include "net/v2_identity.h"
#include "base/hex.h"
#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)

static bool pairing_fixture_write(const char *directory, const uint8_t peer[32],
                                  const uint8_t *wire, size_t length)
{
    char hex[65], path[1200];
    zcl_hex_encode(peer, 32, hex);
    int n = snprintf(path, sizeof(path), "%s/%s.grant", directory, hex);
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool ok = n > 0 && (size_t)n < sizeof(path) &&
        platform_private_file_create(path, &file) &&
        platform_private_file_write_at(&file, wire, length, 0) &&
        platform_private_file_authority_flush(&file);
    platform_private_file_close(&file);
    return ok;
}

static size_t pairing_fixture_length(unsigned version)
{
    switch (version) {
    case 1: return 168;
    case 2: return 176;
    case 4: return 256;
    default: return 288;
    }
}

static void pairing_fixture_scope(uint8_t wire[289], const struct db_device_pairing *row,
    unsigned version)
{
    if (version == 3) {
        memcpy(wire + 144, row->guest_scope.guest_id, 32);
        memcpy(wire + 176, row->guest_scope.requester_ssh_key, 32);
        memcpy(wire + 208, row->guest_scope.owner_grant_root, 32);
        zcl_write_u64_le(wire + 240, row->guest_scope.enrollment_generation);
        zcl_write_u64_le(wire + 248, row->guest_scope.port_mask);
    }
    if (version == 4) {
        wire[144] = (uint8_t)row->host_scope.inbound_port;
        wire[145] = (uint8_t)(row->host_scope.inbound_port >> 8);
        wire[146] = (uint8_t)row->host_scope.outbound_port;
        wire[147] = (uint8_t)(row->host_scope.outbound_port >> 8);
        zcl_write_u64_le(wire + 152, row->host_scope.binding.backend_profile);
        memcpy(wire + 160, row->host_scope.binding.local_pq_key_root, 32);
        memcpy(wire + 192, row->host_scope.binding.peer_pq_key_root, 32);
    }
}

static bool pairing_fixture_version(const char *directory,
    const struct db_device_pairing *row, unsigned version, unsigned defect)
{
    uint8_t wire[289] = {'Z','2','3','D','E','V',0,0};
    size_t length = pairing_fixture_length(version);
    size_t body = length - 32;
    wire[6] = (uint8_t)version;
    memcpy(wire + 8, row->profile, 32);
    memcpy(wire + 40, row->local_key, 32);
    memcpy(wire + 72, row->peer_key, 32);
    zcl_write_u64_le(wire + 104, row->paired_at);
    zcl_write_u64_le(wire + 112, row->expires_at);
    zcl_write_u64_le(wire + 120, row->revoked_at);
    zcl_write_u64_le(wire + 128, row->generation);
    if (version != 1) zcl_write_u64_le(wire + 136, row->capabilities);
    pairing_fixture_scope(wire, row, version);
    if (defect == 6) wire[148] = 1;
    if (defect == 7) { length = 184; body = 152; }
    if (defect == 8) zcl_write_u64_le(wire + 152, UINT64_MAX);
    if (defect == 1) wire[6] = 3;
    if (defect == 4) zcl_write_u64_le(wire + 136, UINT64_C(8));
    if (defect == 5) zcl_write_u64_le(wire + 136, 0);
    zcl_sha3_256(wire, body, wire + body);
    if (defect == 2) length++;
    if (defect == 3) wire[body] ^= 1;
    return pairing_fixture_write(directory, row->peer_key, wire, length);
}

static bool pairing_fixture_record(const char *directory,
    const struct db_device_pairing *row, bool legacy, unsigned defect)
{
    return pairing_fixture_version(directory, row, legacy ? 1 : 2, defect);
}

static bool pairing_fixture_v2_exact(const char *directory,
    const struct db_device_pairing *row)
{
    char hex[65], path[1200];
    uint8_t wire[176], digest[32];
    uint64_t length = 0;
    zcl_hex_encode(row->peer_key, 32, hex);
    int n = snprintf(path, sizeof(path), "%s/%s.grant", directory, hex);
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool ok = n > 0 && (size_t)n < sizeof(path) &&
        platform_private_file_open_observation(path, &file) &&
        platform_private_file_size(&file, &length) && length == sizeof(wire) &&
        platform_private_file_read_at(&file, wire, sizeof(wire), 0);
    platform_private_file_close(&file);
    if (!ok) return false;
    zcl_sha3_256(wire, 144, digest);
    return wire[6] == 2 && wire[7] == 0 &&
        zcl_read_u64_le(wire + 136) == row->capabilities &&
        !memcmp(digest, wire + 144, sizeof(digest));
}

static int pairing_legacy_capability(void)
{
    int failures = 0;
    char directory[1024] = {0};
    struct device_pairing_guard guard = {0};
    TEST_CASE("device_pairing: persisted v1 is status-only before and after sticky v2 revoke") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-legacy-cap"));
        struct db_device_pairing row = {.profile = {1}, .local_key = {2},
            .peer_key = {3}, .paired_at = 100, .expires_at = 200};
        struct device_pairing_store store;
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        ASSERT(pairing_fixture_record(directory, &row, true, 0));
        ASSERT(db_device_pairing_find(&store, row.peer_key, &row));
        ASSERT_EQ(row.capabilities, DEVICE_PAIRING_CAP_STATUS_READ);
        ASSERT(device_pairing_guard_acquire(&store, row.peer_key, 150, &guard));
        device_pairing_guard_release(&guard);
        ASSERT(!device_pairing_guard_acquire_capability(&store, row.peer_key, 150,
            DEVICE_PAIRING_CAP_GUEST_STREAM, &guard));
        enum device_pairing_publication publication;
        ASSERT(db_device_pairing_revoke(&store, row.peer_key, 150, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_DURABLE);
        ASSERT(db_device_pairing_find(&store, row.peer_key, &row));
        ASSERT_EQ(row.capabilities, DEVICE_PAIRING_CAP_STATUS_READ);
        ASSERT_EQ(row.generation, 1);
        ASSERT(pairing_fixture_v2_exact(directory, &row));
        ASSERT(!device_pairing_guard_acquire(&store, row.peer_key, 151, &guard));
    } TEST_END
    device_pairing_guard_release(&guard);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static int pairing_capability_rows(void)
{
    int failures = 0;
    char directory[1024] = {0};
    struct device_pairing_guard guard = {0};
    TEST_CASE("device_pairing: explicit persisted capabilities require the complete requested subset") {
        for (uint64_t caps = 0; caps <= (DEVICE_PAIRING_CAP_STATUS_READ | DEVICE_PAIRING_CAP_GUEST_STREAM); caps++) {
            ASSERT(test_mkdtemp(directory, sizeof(directory), "device-cap-row"));
            struct db_device_pairing row = {.profile = {1}, .local_key = {2},
                .peer_key = {3}, .paired_at = 100, .expires_at = 200,
                .capabilities = caps};
            struct device_pairing_store store, reopened;
            uint8_t fingerprint[32];
            enum device_pairing_publication publication;
            ASSERT(v2_identity_public_fingerprint(row.peer_key, fingerprint));
            ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
            ASSERT(db_device_pairing_insert(&store, &row, fingerprint, &publication));
            ASSERT_EQ(publication, DEVICE_PAIRING_DURABLE);
            uint64_t expected = caps ? caps : DEVICE_PAIRING_CAP_STATUS_READ;
            ASSERT_EQ(row.capabilities, expected);
            ASSERT(pairing_fixture_v2_exact(directory, &row));
            ASSERT(device_pairing_store_open(&reopened, directory, row.profile, row.local_key));
            struct db_device_pairing read;
            ASSERT(db_device_pairing_find(&reopened, row.peer_key, &read));
            ASSERT_EQ(read.capabilities, expected);
            for (uint64_t required = 1; required <= (DEVICE_PAIRING_CAP_STATUS_READ | DEVICE_PAIRING_CAP_GUEST_STREAM); required++) {
                bool admitted = device_pairing_guard_acquire_capability(&reopened,
                    row.peer_key, 150, required, &guard);
                ASSERT_EQ(admitted, (expected & required) == required);
                device_pairing_guard_release(&guard);
            }
            ASSERT_EQ(device_pairing_guard_acquire(&reopened, row.peer_key, 150, &guard),
                (expected & DEVICE_PAIRING_CAP_STATUS_READ) != 0);
            device_pairing_guard_release(&guard);
            ASSERT(!device_pairing_guard_acquire_capability(&store, row.peer_key, 150, 0, &guard));
            ASSERT(!device_pairing_guard_acquire_capability(&store, row.peer_key, 150, 16, &guard));
            ASSERT(!device_pairing_guard_acquire_capability(&store, row.peer_key, 200, expected, &guard));
            row.capabilities = (DEVICE_PAIRING_CAP_STATUS_READ | DEVICE_PAIRING_CAP_GUEST_STREAM);
            ASSERT(!db_device_pairing_insert(&store, &row, fingerprint, &publication));
            ASSERT(db_device_pairing_find(&store, row.peer_key, &read));
            ASSERT_EQ(read.capabilities, expected);
            ASSERT(db_device_pairing_revoke(&store, row.peer_key, 150, &publication));
            ASSERT(!device_pairing_guard_acquire_capability(&store, row.peer_key, 151, expected, &guard));
            test_rm_rf(directory); directory[0] = 0;
        }
    } TEST_END
    device_pairing_guard_release(&guard);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static int pairing_capability_corruption(void)
{
    int failures = 0;
    char directory[1024] = {0};
    struct device_pairing_guard guard = {0};
    TEST_CASE("device_pairing: durable v2 version length digest and capability corruption refuse") {
        for (unsigned defect = 1; defect <= 5; defect++) {
            ASSERT(test_mkdtemp(directory, sizeof(directory), "device-cap-corrupt"));
            struct db_device_pairing row = {.profile = {1}, .local_key = {2},
                .peer_key = {3}, .paired_at = 100, .expires_at = 200,
                .capabilities = (DEVICE_PAIRING_CAP_STATUS_READ | DEVICE_PAIRING_CAP_GUEST_STREAM)};
            struct device_pairing_store store;
            ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
            ASSERT(pairing_fixture_record(directory, &row, false, defect));
            ASSERT(!db_device_pairing_find(&store, row.peer_key, &row));
            ASSERT(!device_pairing_guard_acquire_capability(&store, row.peer_key, 150,
                DEVICE_PAIRING_CAP_GUEST_STREAM, &guard));
            enum device_pairing_publication publication;
            ASSERT(!db_device_pairing_revoke(&store, row.peer_key, 150, &publication));
            test_rm_rf(directory); directory[0] = 0;
        }
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-cap-unknown"));
        struct db_device_pairing row = {.profile = {1}, .local_key = {2},
            .peer_key = {3}, .paired_at = 100, .expires_at = 200, .capabilities = 16};
        struct device_pairing_store store;
        uint8_t fingerprint[32];
        enum device_pairing_publication publication;
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        ASSERT(v2_identity_public_fingerprint(row.peer_key, fingerprint));
        ASSERT(!db_device_pairing_insert(&store, &row, fingerprint, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
    } TEST_END
    device_pairing_guard_release(&guard);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static int pairing_lifecycle(void)
{
    int failures = 0;
    char directory[1024] = {0};
    struct device_pairing_guard guard = {0};
    struct device_pairing_guard concurrent = {0};
    TEST_CASE("device_pairing: confirmation, restart, expiry and serialized sticky revocation") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-pair"));
        struct device_pairing_store store, reopened;
        struct db_device_pairing row = {.profile = {1}, .local_key = {2},
            .peer_key = {3}, .paired_at = 100, .expires_at = 200};
        uint8_t fingerprint[32], wrong[32] = {1};
        ASSERT(v2_identity_public_fingerprint(row.peer_key, fingerprint));
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        enum device_pairing_publication publication;
        ASSERT(!db_device_pairing_insert(&store, &row, wrong, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
        ASSERT(db_device_pairing_insert(&store, &row, fingerprint, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_DURABLE);
        ASSERT(device_pairing_store_open(&reopened, directory, row.profile, row.local_key));
        ASSERT(!device_pairing_guard_acquire(&reopened, row.peer_key, 99, &guard));
        ASSERT(!device_pairing_guard_acquire(&reopened, row.peer_key, 200, &guard));
        ASSERT(device_pairing_guard_acquire(&reopened, row.peer_key, 150, &guard));
        ASSERT(device_pairing_guard_acquire(&reopened, row.peer_key, 150, &concurrent));
        ASSERT(!db_device_pairing_revoke(&store, row.peer_key, 150, &publication));
        device_pairing_guard_release(&concurrent);
        ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
        device_pairing_guard_release(&guard);
        ASSERT(db_device_pairing_revoke(&store, row.peer_key, 150, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_DURABLE);
        ASSERT(!device_pairing_guard_acquire(&reopened, row.peer_key, 151, &guard));
        ASSERT(db_device_pairing_revoke(&reopened, row.peer_key, 152, &publication));
        struct db_device_pairing read;
        ASSERT(db_device_pairing_find(&reopened, row.peer_key, &read));
        ASSERT_EQ(read.revoked_at, 150);
        ASSERT_EQ(read.generation, 1);
        ASSERT(!db_device_pairing_insert(&store, &row, fingerprint, &publication));
    } TEST_END
    device_pairing_guard_release(&concurrent);
    device_pairing_guard_release(&guard);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static int pairing_corruption(void)
{
    int failures = 0;
    char directory[1024] = {0};
    struct platform_private_file file;
    platform_private_file_init(&file);
    struct device_pairing_guard guard = {0};
    TEST_CASE("device_pairing: interrupted publication, corrupt authority and wrong profile refuse") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-corrupt"));
        struct device_pairing_store store, other;
        struct db_device_pairing row = {.profile = {1}, .local_key = {2},
            .peer_key = {3}, .paired_at = 100, .expires_at = 200};
        uint8_t fingerprint[32], other_profile[32] = {9};
        ASSERT(v2_identity_public_fingerprint(row.peer_key, fingerprint));
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        enum device_pairing_publication publication;
        ASSERT(db_device_pairing_insert(&store, &row, fingerprint, &publication));
        ASSERT(device_pairing_store_open(&other, directory, other_profile, row.local_key));
        ASSERT(!device_pairing_guard_acquire(&other, row.peer_key, 150, &guard));
        char hex[65], path[1200], pending[1240];
        zcl_hex_encode(row.peer_key, 32, hex);
        ASSERT(snprintf(path, sizeof(path), "%s/%s.grant", directory, hex) > 0);
        ASSERT(snprintf(pending, sizeof(pending), "%s.pending", path) > 0);
        ASSERT(platform_private_file_create(pending, &file));
        ASSERT(!device_pairing_guard_acquire(&store, row.peer_key, 150, &guard));
        ASSERT(platform_private_file_retire(&file, pending));
        ASSERT(device_pairing_guard_acquire(&store, row.peer_key, 150, &guard));
        device_pairing_guard_release(&guard);
        ASSERT(platform_private_file_open_locked(path, &file));
        uint8_t corrupt = 0xff;
        ASSERT(platform_private_file_write_at(&file, &corrupt, 1, 120));
        platform_private_file_close(&file);
        ASSERT(!device_pairing_guard_acquire(&store, row.peer_key, 150, &guard));
        ASSERT(!db_device_pairing_revoke(&store, row.peer_key, 150, &publication));
    } TEST_END
    platform_private_file_close(&file);
    device_pairing_guard_release(&guard);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}


static struct db_device_pairing pairing_bind_row(void);

static int pairing_publication_interruptions(bool bind)
{
    int failures = 0;
    char directory[1024] = {0};
    struct device_pairing_guard guard = {0};
    TEST_CASE("device_pairing: actual insert and revoke interruption boundaries fail closed") {
        for (unsigned revoke = 0; revoke < 2; ++revoke) {
            for (unsigned stage = 1; stage <= 3; ++stage) {
                ASSERT(test_mkdtemp(directory, sizeof(directory), "device-intent"));
                struct device_pairing_store store, reopened;
                struct db_device_pairing row = {.profile = {1}, .local_key = {2},
                    .peer_key = {3}, .paired_at = 100, .expires_at = 200,
                    .capabilities = (DEVICE_PAIRING_CAP_STATUS_READ | DEVICE_PAIRING_CAP_GUEST_STREAM)};
                if (bind) row = pairing_bind_row();
                uint8_t fingerprint[32];
                ASSERT(v2_identity_public_fingerprint(row.peer_key, fingerprint));
                ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
                enum device_pairing_publication publication;
                if (revoke)
                    ASSERT(db_device_pairing_insert(&store, &row, fingerprint, &publication));
                device_pairing_test_interrupt(stage);
                bool ok = revoke ?
                    db_device_pairing_revoke(&store, row.peer_key, 150, &publication) :
                    db_device_pairing_insert(&store, &row, fingerprint, &publication);
                ASSERT(!ok);
                ASSERT_EQ(publication, stage == 1 ? DEVICE_PAIRING_NOT_PUBLISHED :
                                                     DEVICE_PAIRING_DURABILITY_UNKNOWN);
                ASSERT(device_pairing_store_open(&reopened, directory, row.profile, row.local_key));
                ASSERT(!device_pairing_guard_acquire(&reopened, row.peer_key, 151, &guard));
                if (bind) {
                    ASSERT(!device_pairing_guard_acquire_guest_bind(&reopened,
                        row.peer_key, 151, &row.guest_scope, 0, 0, &guard));
                    ASSERT(!guard.held);
                }
                ASSERT(!db_device_pairing_revoke(&reopened, row.peer_key, 151, &publication));
                test_rm_rf(directory);
                directory[0] = '\0';
            }
        }
    } TEST_END
    device_pairing_test_interrupt(0);
    device_pairing_guard_release(&guard);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static struct db_device_pairing pairing_bind_row(void)
{
    return (struct db_device_pairing){.profile = {1}, .local_key = {2},
        .peer_key = {3}, .paired_at = 100, .expires_at = 200,
        .capabilities = DEVICE_PAIRING_CAP_GUEST_STREAM | DEVICE_PAIRING_CAP_GUEST_BIND,
        .guest_scope = {.guest_id = {4}, .requester_ssh_key = {5},
            .owner_grant_root = {6}, .enrollment_generation = 7, .port_mask = 5}};
}

static void pairing_scope_defect(struct device_pairing_guest_scope *scope, unsigned defect)
{
    switch (defect) {
    case 0: memset(scope->guest_id, 0, 32); break;
    case 1: memset(scope->requester_ssh_key, 0, 32); break;
    case 2: memset(scope->owner_grant_root, 0, 32); break;
    case 3: scope->enrollment_generation = 0; break;
    case 4: scope->port_mask = 0; break;
    default: scope->port_mask = 16; break;
    }
}

static bool pairing_bind_refused(struct device_pairing_store *store,
    const uint8_t peer[32], uint64_t now,
    const struct device_pairing_guest_scope *scope, unsigned slot, unsigned role)
{
    struct device_pairing_guard guard = {0};
    bool admitted = device_pairing_guard_acquire_guest_bind(store, peer, now,
        scope, slot, role, &guard);
    bool refused = !admitted && !guard.held;
    device_pairing_guard_release(&guard);
    return refused;
}

static int pairing_bind_validation(void)
{
    int failures = 0;
    TEST_CASE("device_pairing: bind requires stream and complete scope; nonbind forbids scope") {
        struct ar_errors errors;
        struct db_device_pairing row = pairing_bind_row();
        ASSERT(db_device_pairing_validate(&row, &errors));
        for (unsigned defect = 0; defect < 6; defect++) {
            row = pairing_bind_row();
            pairing_scope_defect(&row.guest_scope, defect);
            ASSERT(!db_device_pairing_validate(&row, &errors));
        }
        row = pairing_bind_row(); row.capabilities = DEVICE_PAIRING_CAP_GUEST_BIND;
        ASSERT(!db_device_pairing_validate(&row, &errors));
        row = pairing_bind_row(); row.capabilities |= UINT64_C(16);
        ASSERT(!db_device_pairing_validate(&row, &errors));
        for (unsigned field = 0; field < 5; field++) {
            row = pairing_bind_row(); row.capabilities = DEVICE_PAIRING_CAP_GUEST_STREAM;
            memset(&row.guest_scope, 0, sizeof(row.guest_scope));
            switch (field) {
            case 0: row.guest_scope.guest_id[0] = 1; break;
            case 1: row.guest_scope.requester_ssh_key[0] = 1; break;
            case 2: row.guest_scope.owner_grant_root[0] = 1; break;
            case 3: row.guest_scope.enrollment_generation = 1; break;
            default: row.guest_scope.port_mask = 1; break;
            }
            ASSERT(!db_device_pairing_validate(&row, &errors));
        }
    } TEST_END
    return failures;
}

static int pairing_bind_wire_refusals(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_pairing: v1/v2 cannot bind and malformed v3 fails closed") {
        for (unsigned defect = 0; defect < 12; defect++) {
            ASSERT(test_mkdtemp(directory, sizeof(directory), "device-bind-wire"));
            struct db_device_pairing row = pairing_bind_row(), read;
            struct device_pairing_store store;
            unsigned version = defect < 2 ? defect + 1 : 3;
            if (defect >= 2 && defect < 8) pairing_scope_defect(&row.guest_scope, defect - 2);
            if (defect == 8) row.capabilities = DEVICE_PAIRING_CAP_GUEST_STREAM;
            if (defect == 9) row.capabilities = DEVICE_PAIRING_CAP_GUEST_BIND;
            if (defect == 10) row.capabilities |= UINT64_C(16);
            ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
            ASSERT(pairing_fixture_version(directory, &row, version, defect == 11 ? 3 : 0));
            ASSERT(pairing_bind_refused(&store, row.peer_key, 150, &row.guest_scope, 0, 0));
            if (version == 1) {
                ASSERT(db_device_pairing_find(&store, row.peer_key, &read));
                ASSERT_EQ(read.capabilities, DEVICE_PAIRING_CAP_STATUS_READ);
            } else ASSERT(!db_device_pairing_find(&store, row.peer_key, &read));
            test_rm_rf(directory); directory[0] = 0;
        }
    } TEST_END
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static bool pairing_bind_mismatches(struct device_pairing_store *store,
                                    const struct db_device_pairing *row)
{
    for (unsigned field = 0; field < 5; field++) {
        struct device_pairing_guest_scope scope = row->guest_scope;
        switch (field) {
        case 0: scope.guest_id[31] ^= 1; break;
        case 1: scope.requester_ssh_key[31] ^= 1; break;
        case 2: scope.owner_grant_root[31] ^= 1; break;
        case 3: scope.enrollment_generation++; break;
        default: scope.port_mask = 15; break;
        }
        if (!pairing_bind_refused(store, row->peer_key, 150, &scope, 0, 0)) return false;
    }
    return true;
}

static int pairing_bind_roundtrip(void)
{
    int failures = 0;
    char directory[1024] = {0};
    struct device_pairing_guard guard = {0};
    TEST_CASE("device_pairing: durable v3 exact directional scope, ports and revocation") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-bind-row"));
        struct db_device_pairing row = pairing_bind_row(), read;
        struct device_pairing_store store, reopened, other;
        uint8_t fingerprint[32], wrong[32] = {9};
        enum device_pairing_publication publication;
        ASSERT(v2_identity_public_fingerprint(row.peer_key, fingerprint));
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        ASSERT(db_device_pairing_insert(&store, &row, fingerprint, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_DURABLE);
        ASSERT(device_pairing_store_open(&reopened, directory, row.profile, row.local_key));
        memset(&read, 0xff, sizeof(read));
        ASSERT(db_device_pairing_find(&reopened, row.peer_key, &read));
        ASSERT(!memcmp(&read.guest_scope, &row.guest_scope, sizeof(row.guest_scope)));
        ASSERT_EQ(read.capabilities, row.capabilities);
        ASSERT(pairing_bind_mismatches(&reopened, &row));
        for (unsigned port = 0; port < 4; port++) {
            bool admitted = device_pairing_guard_acquire_guest_bind(&reopened,
                row.peer_key, 150, &row.guest_scope, port / 2, port % 2, &guard);
            ASSERT_EQ(admitted, (row.guest_scope.port_mask & (UINT64_C(1) << port)) != 0);
            ASSERT_EQ(guard.held, admitted);
            device_pairing_guard_release(&guard);
        }
        ASSERT(pairing_bind_refused(&store, row.peer_key, 150, &row.guest_scope, 2, 0));
        ASSERT(pairing_bind_refused(&store, row.peer_key, 150, &row.guest_scope, 0, 2));
        ASSERT(pairing_bind_refused(&store, row.peer_key, 150, NULL, 0, 0));
        ASSERT(pairing_bind_refused(&store, row.peer_key, 99, &row.guest_scope, 0, 0));
        ASSERT(pairing_bind_refused(&store, row.peer_key, 200, &row.guest_scope, 0, 0));
        ASSERT(pairing_bind_refused(&store, wrong, 150, &row.guest_scope, 0, 0));
        ASSERT(device_pairing_store_open(&other, directory, wrong, row.local_key));
        ASSERT(pairing_bind_refused(&other, row.peer_key, 150, &row.guest_scope, 0, 0));
        ASSERT(device_pairing_store_open(&other, directory, row.profile, wrong));
        ASSERT(pairing_bind_refused(&other, row.peer_key, 150, &row.guest_scope, 0, 0));
        ASSERT(!device_pairing_guard_acquire_capability(&store, row.peer_key, 150,
            DEVICE_PAIRING_CAP_GUEST_BIND, &guard));
        ASSERT(db_device_pairing_revoke(&store, row.peer_key, 150, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_DURABLE);
        ASSERT(db_device_pairing_find(&reopened, row.peer_key, &read));
        ASSERT(!memcmp(&read.guest_scope, &row.guest_scope, sizeof(row.guest_scope)));
        ASSERT(pairing_bind_refused(&reopened, row.peer_key, 151, &row.guest_scope, 0, 0));
    } TEST_END
    device_pairing_guard_release(&guard);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static bool pairing_fixture_root(const char *directory, const uint8_t peer[32],
    uint8_t root[32])
{
    char hex[65], path[1200];
    zcl_hex_encode(peer, 32, hex);
    int n = snprintf(path, sizeof(path), "%s/%s.grant", directory, hex);
    struct platform_private_file file;
    platform_private_file_init(&file);
    uint64_t length = 0;
    uint8_t wire[288];
    bool ok = n > 0 && (size_t)n < sizeof(path) &&
        platform_private_file_open_observation(path, &file) &&
        platform_private_file_size(&file, &length) && length <= sizeof(wire) &&
        platform_private_file_read_at(&file, wire, (size_t)length, 0);
    platform_private_file_close(&file);
    if (ok) zcl_sha3_256(wire, (size_t)length, root);
    return ok;
}

static int pairing_inspection_roots(void)
{
    int failures = 0;
    char directory[1024] = {0};
    struct device_pairing_guard guard = {0};
    TEST_CASE("device_pairing: inspection hashes exact v1 v2 v3 full wire") {
        for (unsigned version = 1; version <= 3; ++version) {
            ASSERT(test_mkdtemp(directory, sizeof(directory), "device-inspect"));
            struct db_device_pairing row = pairing_bind_row(), found;
            if (version != 3) {
                row.capabilities = DEVICE_PAIRING_CAP_STATUS_READ;
                memset(&row.guest_scope, 0, sizeof(row.guest_scope));
            }
            struct device_pairing_store store;
            uint8_t root[32], exact[32];
            uint8_t fingerprint[32];
            enum device_pairing_publication publication;
            ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
            ASSERT(pairing_fixture_version(directory, &row, version, 0));
            ASSERT(v2_identity_public_fingerprint(row.peer_key, fingerprint));
            ASSERT(!db_device_pairing_insert(&store, &row, fingerprint, &publication));
            ASSERT(pairing_fixture_root(directory, row.peer_key, exact));
            ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root));
            ASSERT(!memcmp(root, exact, 32));
            ASSERT(device_pairing_guard_acquire_capability(&store, row.peer_key, 150,
                version == 3 ? DEVICE_PAIRING_CAP_GUEST_STREAM : DEVICE_PAIRING_CAP_STATUS_READ, &guard));
            ASSERT(!memcmp(guard.root, exact, 32));
            ASSERT(!memcmp(guard.root, root, 32));
            device_pairing_guard_release(&guard);
            ASSERT_EQ(found.capabilities, row.capabilities);
            uint8_t missing[32] = {9};
            struct db_device_pairing saved = found;
            ASSERT(!db_device_pairing_inspect(&store, missing, &found, root));
            ASSERT(!memcmp(&found, &saved, sizeof(found)));
            ASSERT(!memcmp(root, exact, 32));
            test_rm_rf(directory); directory[0] = '\0';
        }
    } TEST_END
    device_pairing_guard_release(&guard);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static void pairing_upgrade_defect(struct db_device_pairing *row, unsigned defect)
{
    switch (defect) {
    case 2: row->profile[0]++; break;
    case 3: row->local_key[0]++; break;
    case 4: row->peer_key[0]++; break;
    case 5: row->paired_at++; break;
    case 6: row->expires_at = 150; break;
    case 7: row->guest_scope.port_mask = 16; break;
    case 8: row->capabilities = 0; break;
    case 9: row->revoked_at = 150; row->generation = 1; break;
    case 10: row->generation = 1; break;
    default: break;
    }
}

static int pairing_upgrade_refusals(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_pairing: exact upgrade refuses stale identity expiry and invalid authority") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-upgrade-refuse"));
        struct db_device_pairing row = pairing_bind_row(), current;
        row.capabilities = DEVICE_PAIRING_CAP_STATUS_READ;
        memset(&row.guest_scope, 0, sizeof(row.guest_scope));
        struct device_pairing_store store;
        uint8_t root[32], fingerprint[32], after[32];
        enum device_pairing_publication publication;
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        ASSERT(v2_identity_public_fingerprint(row.peer_key, fingerprint));
        ASSERT(db_device_pairing_insert(&store, &row, fingerprint, &publication));
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &current, root));
        for (unsigned defect = 0; defect <= 12; ++defect) {
            struct db_device_pairing replacement = pairing_bind_row();
            uint8_t expected[32], confirmed[32];
            memcpy(expected, root, 32); memcpy(confirmed, fingerprint, 32);
            if (defect == 0) expected[0] ^= 1;
            if (defect == 1) confirmed[0] ^= 1;
            pairing_upgrade_defect(&replacement, defect);
            uint64_t now = defect == 11 ? 200 : (defect == 12 ? 99 : 150);
            ASSERT(!db_device_pairing_upgrade(&store, &replacement, confirmed, expected, now, &publication));
            ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
            ASSERT(db_device_pairing_inspect(&store, row.peer_key, &current, after));
            ASSERT(!memcmp(root, after, 32));
        }
        ASSERT(db_device_pairing_revoke(&store, row.peer_key, 150, &publication));
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &current, root));
        struct db_device_pairing replacement = pairing_bind_row();
        ASSERT(!db_device_pairing_upgrade(&store, &replacement, fingerprint, root, 151, &publication));
        ASSERT(!db_device_pairing_insert(&store, &row, fingerprint, &publication));
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &current, after));
        ASSERT(!memcmp(root, after, 32));
    } TEST_END
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static int pairing_upgrade_publication(void)
{
    int failures = 0;
    char directory[1024] = {0};
    struct device_pairing_guard guard = {0};
    TEST_CASE("device_pairing: v2 to scoped v3 upgrade and pending interruption refusal") {
        for (unsigned stage = 0; stage <= 3; ++stage) {
            ASSERT(test_mkdtemp(directory, sizeof(directory), "device-upgrade"));
            struct db_device_pairing replacement = pairing_bind_row(), row = replacement, found;
            row.capabilities = DEVICE_PAIRING_CAP_STATUS_READ;
            memset(&row.guest_scope, 0, sizeof(row.guest_scope));
            struct device_pairing_store store, reopened;
            uint8_t fingerprint[32], root[32], after[32];
            enum device_pairing_publication publication;
            ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
            ASSERT(v2_identity_public_fingerprint(row.peer_key, fingerprint));
            ASSERT(db_device_pairing_insert(&store, &row, fingerprint, &publication));
            ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root));
            device_pairing_test_interrupt(stage);
            ASSERT_EQ(db_device_pairing_upgrade(&store, &replacement, fingerprint, root, 150, &publication), stage == 0);
            ASSERT_EQ(publication, stage == 0 ? DEVICE_PAIRING_DURABLE :
                (stage == 1 ? DEVICE_PAIRING_NOT_PUBLISHED : DEVICE_PAIRING_DURABILITY_UNKNOWN));
            ASSERT(device_pairing_store_open(&reopened, directory, row.profile, row.local_key));
            if (!stage) {
                ASSERT(db_device_pairing_inspect(&reopened, row.peer_key, &found, after));
                ASSERT(memcmp(root, after, 32));
                ASSERT(pairing_fixture_root(directory, row.peer_key, root));
                ASSERT(!memcmp(root, after, 32));
                ASSERT(device_pairing_guard_acquire_guest_bind(&reopened, row.peer_key, 151,
                    &replacement.guest_scope, 0, 0, &guard));
                device_pairing_guard_release(&guard);
                ASSERT(pairing_bind_mismatches(&reopened, &replacement));
                ASSERT(!db_device_pairing_insert(&store, &row, fingerprint, &publication));
                ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root));
                ASSERT(!memcmp(root, after, 32));
            } else {
                struct db_device_pairing saved = found;
                memcpy(after, root, 32);
                ASSERT(!db_device_pairing_inspect(&reopened, row.peer_key, &found, after));
                ASSERT(!memcmp(&found, &saved, sizeof(found)));
                ASSERT(!memcmp(root, after, 32));
                ASSERT(!db_device_pairing_upgrade(&reopened, &replacement, fingerprint, root, 151, &publication));
                ASSERT(!db_device_pairing_insert(&reopened, &row, fingerprint, &publication));
                ASSERT(pairing_bind_refused(&reopened, row.peer_key, 151, &replacement.guest_scope, 0, 0));
            }
            test_rm_rf(directory); directory[0] = '\0';
        }
    } TEST_END
    device_pairing_test_interrupt(0);
    device_pairing_guard_release(&guard);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static int pairing_expected_revoke(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_pairing: exact-root revocation refuses a stale approval after upgrade") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-revoke-root"));
        struct device_pairing_store store;
        struct db_device_pairing replacement = pairing_bind_row(), row = replacement, current;
        row.capabilities = DEVICE_PAIRING_CAP_STATUS_READ;
        memset(&row.guest_scope, 0, sizeof(row.guest_scope));
        uint8_t fingerprint[32], old_root[32], current_root[32], observed[32];
        enum device_pairing_publication publication;
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        ASSERT(v2_identity_public_fingerprint(row.peer_key, fingerprint));
        ASSERT(db_device_pairing_insert(&store, &row, fingerprint, &publication));
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &current, old_root));
        ASSERT(db_device_pairing_upgrade(&store, &replacement, fingerprint, old_root, 150, &publication));
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &current, current_root));
        ASSERT(memcmp(old_root, current_root, 32));
        ASSERT(!db_device_pairing_revoke_expected(&store, row.peer_key, 151, NULL, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
        ASSERT(!db_device_pairing_revoke_expected(&store, row.peer_key, 151, old_root, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &current, observed));
        ASSERT(!memcmp(current_root, observed, 32));
        ASSERT_EQ(current.revoked_at, 0);
        ASSERT(db_device_pairing_revoke_expected(&store, row.peer_key, 151, current_root, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_DURABLE);
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &current, observed));
        ASSERT_EQ(current.revoked_at, 151);
        ASSERT_EQ(current.generation, 1);
        ASSERT(db_device_pairing_revoke_expected(&store, row.peer_key, 152, observed, &publication));
        ASSERT(db_device_pairing_find(&store, row.peer_key, &current));
        ASSERT_EQ(current.revoked_at, 151);
        ASSERT_EQ(current.generation, 1);
    } TEST_END
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static struct db_device_pairing pairing_host_row(void)
{
    return (struct db_device_pairing){.profile = {1}, .local_key = {2},
        .peer_key = {3}, .paired_at = 100, .expires_at = 200,
        .capabilities = DEVICE_PAIRING_CAP_HOST_FORWARD,
        .host_scope = {.inbound_port = 2222, .outbound_port = 3333,
            .binding = {.backend_profile = DEVICE_PAIRING_HOST_OPENSSH_MLKEM768X25519_MLDSA44ED25519,
                .local_pq_key_root = {4}, .peer_pq_key_root = {5}}}};
}

static bool pairing_host_refused(struct device_pairing_store *store,
    const uint8_t peer[32], uint64_t now,
    enum device_pairing_host_direction direction, uint16_t port)
{
    struct device_pairing_guard guard = {0};
    struct db_device_pairing row = pairing_host_row();
    bool admitted = device_pairing_guard_acquire_host_forward(store, peer, now,
        &row.host_scope.binding,
        direction, port, &guard);
    bool held = guard.held;
    device_pairing_guard_release(&guard);
    return !admitted && !held;
}

static int pairing_host_validation(void)
{
    int failures = 0;
    TEST_CASE("device_pairing: host scope requires explicit unmixed authority") {
        struct db_device_pairing row = pairing_host_row();
        struct ar_errors errors;
        ASSERT(db_device_pairing_validate(&row, &errors));
        row.capabilities |= DEVICE_PAIRING_CAP_STATUS_READ;
        ASSERT(db_device_pairing_validate(&row, &errors));
        row.capabilities |= DEVICE_PAIRING_CAP_GUEST_STREAM;
        ASSERT(!db_device_pairing_validate(&row, &errors));
        row = pairing_host_row(); row.host_scope = (struct device_pairing_host_scope){0};
        ASSERT(!db_device_pairing_validate(&row, &errors));
        row = pairing_host_row(); row.capabilities = DEVICE_PAIRING_CAP_STATUS_READ;
        ASSERT(!db_device_pairing_validate(&row, &errors));
        row = pairing_host_row(); row.guest_scope.guest_id[0] = 1;
        ASSERT(!db_device_pairing_validate(&row, &errors));
        row = pairing_host_row(); row.host_scope.binding.backend_profile = 2;
        ASSERT(!db_device_pairing_validate(&row, &errors));
        row = pairing_host_row(); memset(row.host_scope.binding.local_pq_key_root, 0, 32);
        ASSERT(!db_device_pairing_validate(&row, &errors));
        row = pairing_host_row(); memset(row.host_scope.binding.peer_pq_key_root, 0, 32);
        ASSERT(!db_device_pairing_validate(&row, &errors));
        row = pairing_host_row(); row.host_scope.inbound_port = 0; row.host_scope.outbound_port = 0;
        row.capabilities = DEVICE_PAIRING_CAP_STATUS_READ;
        ASSERT(!db_device_pairing_validate(&row, &errors));
    } TEST_END
    return failures;
}

static int pairing_host_directions(void)
{
    int failures = 0;
    char directory[1024] = {0};
    struct device_pairing_guard guard = {0};
    TEST_CASE("device_pairing: v4 host directions require exact nonzero local ports") {
        for (unsigned enabled = 1; enabled <= 3; ++enabled) {
            ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host"));
            struct db_device_pairing row = pairing_host_row(), found;
            if (!(enabled & 1)) row.host_scope.inbound_port = 0;
            if (!(enabled & 2)) row.host_scope.outbound_port = 0;
            struct device_pairing_store store;
            uint8_t fingerprint[32], root[32], exact[32];
            enum device_pairing_publication publication;
            ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
            ASSERT(device_pairing_host_proposal_root(&row, fingerprint));
            ASSERT(db_device_pairing_insert_host(&store, &row, fingerprint, &publication));
            ASSERT_EQ(publication, DEVICE_PAIRING_DURABLE);
            ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root));
            ASSERT(pairing_fixture_root(directory, row.peer_key, exact));
            ASSERT(!memcmp(root, exact, 32));
            ASSERT_EQ(found.host_scope.inbound_port, row.host_scope.inbound_port);
            ASSERT_EQ(found.host_scope.outbound_port, row.host_scope.outbound_port);
            for (unsigned direction = 0; direction < 2; ++direction) {
                uint16_t port = direction ? 3333 : 2222;
                bool admitted = device_pairing_guard_acquire_host_forward(&store,
                    row.peer_key, 150, &row.host_scope.binding, (enum device_pairing_host_direction)direction, port, &guard);
                ASSERT_EQ(admitted, (enabled & (1U << direction)) != 0);
                ASSERT_EQ(guard.held, admitted);
                device_pairing_guard_release(&guard);
                ASSERT(pairing_host_refused(&store, row.peer_key, 150,
                    (enum device_pairing_host_direction)direction, direction ? 2222 : 3333));
                ASSERT(pairing_host_refused(&store, row.peer_key, 150,
                    (enum device_pairing_host_direction)direction, 0));
            }
            ASSERT(!device_pairing_guard_acquire_capability(&store, row.peer_key, 150,
                DEVICE_PAIRING_CAP_HOST_FORWARD, &guard));
            ASSERT(pairing_host_refused(&store, row.peer_key, 150,
                (enum device_pairing_host_direction)2, 2222));
            ASSERT(pairing_host_refused(&store, row.peer_key, 99, DEVICE_PAIRING_HOST_INBOUND, 2222));
            ASSERT(pairing_host_refused(&store, row.peer_key, 200, DEVICE_PAIRING_HOST_OUTBOUND, 3333));
            test_rm_rf(directory); directory[0] = 0;
        }
    } TEST_END
    device_pairing_guard_release(&guard);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static int pairing_host_wire(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_pairing: old versions never grant host and malformed v4 refuses") {
        for (unsigned defect = 0; defect < 11; ++defect) {
            ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-wire"));
            struct db_device_pairing row = pairing_host_row(), found;
            struct device_pairing_store store;
            unsigned version = defect < 3 ? defect + 1 : 4;
            if (defect == 3) row.host_scope = (struct device_pairing_host_scope){0};
            if (defect == 4) row.capabilities |= DEVICE_PAIRING_CAP_GUEST_STREAM;
            if (defect == 5) row.capabilities = DEVICE_PAIRING_CAP_STATUS_READ;
            static const unsigned defects[] = {0, 0, 0, 0, 0, 0, 6, 2, 3, 7, 8};
            unsigned wire_defect = defects[defect];
            ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
            ASSERT(pairing_fixture_version(directory, &row, version, wire_defect));
            ASSERT(pairing_host_refused(&store, row.peer_key, 150, DEVICE_PAIRING_HOST_INBOUND, 2222));
            if (version == 1) {
                ASSERT(db_device_pairing_find(&store, row.peer_key, &found));
                ASSERT_EQ(found.capabilities, DEVICE_PAIRING_CAP_STATUS_READ);
                ASSERT_EQ(found.host_scope.inbound_port, 0);
            } else ASSERT(!db_device_pairing_find(&store, row.peer_key, &found));
            test_rm_rf(directory); directory[0] = 0;
        }
    } TEST_END
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static int pairing_host_upgrade(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_pairing: host upgrade requires exact root and revoked host remains revoked") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-upgrade"));
        struct db_device_pairing replacement = pairing_host_row(), row = replacement, found;
        row.capabilities = DEVICE_PAIRING_CAP_STATUS_READ;
        row.host_scope = (struct device_pairing_host_scope){0};
        struct device_pairing_store store;
        uint8_t fingerprint[32], root[32], current[32], stale[32] = {9};
        uint8_t proposal[32];
        enum device_pairing_publication publication;
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        ASSERT(v2_identity_public_fingerprint(row.peer_key, fingerprint));
        ASSERT(device_pairing_host_proposal_root(&replacement, proposal));
        ASSERT(db_device_pairing_insert(&store, &row, fingerprint, &publication));
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root));
        ASSERT(pairing_host_refused(&store, row.peer_key, 150, DEVICE_PAIRING_HOST_INBOUND, 2222));
        ASSERT(!db_device_pairing_upgrade(&store, &replacement, fingerprint, root, 150, &publication));
        ASSERT(!db_device_pairing_upgrade_host(&store, &replacement, proposal, stale, 150, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
        ASSERT(db_device_pairing_upgrade_host(&store, &replacement, proposal, root, 150, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_DURABLE);
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, current));
        ASSERT(memcmp(root, current, 32));
        ASSERT_EQ(found.paired_at, row.paired_at);
        ASSERT(!db_device_pairing_upgrade_host(&store, &replacement, proposal, root, 150, &publication));
        ASSERT(db_device_pairing_revoke_expected(&store, row.peer_key, 151, current, &publication));
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, current));
        ASSERT_EQ(found.host_scope.inbound_port, 2222);
        ASSERT_EQ(found.host_scope.outbound_port, 3333);
        ASSERT_EQ(found.revoked_at, 151);
        ASSERT(pairing_host_refused(&store, row.peer_key, 152, DEVICE_PAIRING_HOST_INBOUND, 2222));
        ASSERT(!db_device_pairing_upgrade_host(&store, &replacement, proposal, current, 152, &publication));
    } TEST_END
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static int pairing_host_interruptions(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_pairing: interrupted host insert and revoke fail closed") {
        for (unsigned revoke = 0; revoke < 2; ++revoke) {
            for (unsigned stage = 1; stage <= 3; ++stage) {
                ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-interrupt"));
                struct db_device_pairing row = pairing_host_row();
                struct device_pairing_store store;
                uint8_t fingerprint[32];
                enum device_pairing_publication publication;
                ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
                ASSERT(device_pairing_host_proposal_root(&row, fingerprint));
                if (revoke) ASSERT(db_device_pairing_insert_host(&store, &row, fingerprint, &publication));
                device_pairing_test_interrupt(stage);
                bool ok = revoke ? db_device_pairing_revoke(&store, row.peer_key, 150, &publication) :
                    db_device_pairing_insert_host(&store, &row, fingerprint, &publication);
                ASSERT(!ok);
                ASSERT_EQ(publication, stage == 1 ? DEVICE_PAIRING_NOT_PUBLISHED : DEVICE_PAIRING_DURABILITY_UNKNOWN);
                ASSERT(pairing_host_refused(&store, row.peer_key, 151, DEVICE_PAIRING_HOST_INBOUND, 2222));
                test_rm_rf(directory); directory[0] = 0;
            }
        }
    } TEST_END
    device_pairing_test_interrupt(0);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static void pairing_host_proposal_change(struct db_device_pairing *row, unsigned field)
{
    switch (field) {
    case 0: row->profile[31] ^= 1; break;
    case 1: row->local_key[31] ^= 1; break;
    case 2: row->peer_key[31] ^= 1; break;
    case 3: row->paired_at++; break;
    case 4: row->expires_at++; break;
    case 5: row->capabilities |= DEVICE_PAIRING_CAP_STATUS_READ; break;
    case 6: row->host_scope.inbound_port++; break;
    case 7: row->host_scope.outbound_port++; break;
    case 8: row->host_scope.binding.backend_profile++; break;
    case 9: row->host_scope.binding.local_pq_key_root[31] ^= 1; break;
    default: row->host_scope.binding.peer_pq_key_root[31] ^= 1; break;
    }
}

static int pairing_host_confirmations(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_pairing: owner approval covers every host proposal field") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-confirm"));
        struct db_device_pairing row = pairing_host_row(), found;
        struct device_pairing_store store;
        uint8_t proposal[32], fingerprint[32];
        enum device_pairing_publication publication;
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        ASSERT(device_pairing_host_proposal_root(&row, proposal));
        ASSERT(v2_identity_public_fingerprint(row.peer_key, fingerprint));
        ASSERT(!db_device_pairing_insert(&store, &row, fingerprint, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
        ASSERT(!db_device_pairing_insert(&store, &row, proposal, &publication));
        ASSERT(!db_device_pairing_insert_host(&store, &row, fingerprint, &publication));
        ASSERT(!db_device_pairing_insert_host(&store, &row, NULL, &publication));
        for (unsigned field = 0; field < 11; ++field) {
            struct db_device_pairing changed = row;
            pairing_host_proposal_change(&changed, field);
            ASSERT(!db_device_pairing_insert_host(&store, &changed, proposal, &publication));
            ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
            ASSERT(!db_device_pairing_find(&store, changed.peer_key, &found));
        }
        ASSERT(db_device_pairing_insert_host(&store, &row, proposal, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_DURABLE);
        ASSERT(db_device_pairing_find(&store, row.peer_key, &found));
        ASSERT_EQ(found.host_scope.binding.backend_profile, row.host_scope.binding.backend_profile);
        ASSERT(!memcmp(found.host_scope.binding.local_pq_key_root, row.host_scope.binding.local_pq_key_root, 32));
        ASSERT(!memcmp(found.host_scope.binding.peer_pq_key_root, row.host_scope.binding.peer_pq_key_root, 32));
    } TEST_END
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static bool pairing_host_binding_admitted(struct device_pairing_store *store,
    const struct db_device_pairing *row, const struct device_pairing_host_binding *binding)
{
    struct device_pairing_guard guard = {0};
    bool admitted = device_pairing_guard_acquire_host_forward(store, row->peer_key,
        150, binding, DEVICE_PAIRING_HOST_INBOUND, 2222, &guard);
    bool held = guard.held;
    device_pairing_guard_release(&guard);
    return admitted && held;
}

static bool pairing_host_binding_refused(struct device_pairing_store *store,
    const struct db_device_pairing *row, const struct device_pairing_host_binding *binding)
{
    struct device_pairing_guard guard = {0};
    bool admitted = device_pairing_guard_acquire_host_forward(store, row->peer_key,
        150, binding, DEVICE_PAIRING_HOST_INBOUND, 2222, &guard);
    bool held = guard.held;
    device_pairing_guard_release(&guard);
    return !admitted && !held;
}

static int pairing_host_rotation(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_pairing: exact authenticated PQ roots and owner-approved rotation") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-rotate"));
        struct db_device_pairing row = pairing_host_row(), found, replacement = row;
        struct device_pairing_store store;
        uint8_t proposal[32], next_proposal[32], root[32], next_root[32], observed[32];
        enum device_pairing_publication publication;
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        ASSERT(device_pairing_host_proposal_root(&row, proposal));
        ASSERT(db_device_pairing_insert_host(&store, &row, proposal, &publication));
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root));
        ASSERT(pairing_host_binding_admitted(&store, &row, &row.host_scope.binding));
        ASSERT(pairing_host_binding_refused(&store, &row, NULL));
        for (unsigned field = 8; field < 11; ++field) {
            struct db_device_pairing changed = row;
            pairing_host_proposal_change(&changed, field);
            ASSERT(pairing_host_binding_refused(&store, &row, &changed.host_scope.binding));
        }
        replacement.host_scope.binding.peer_pq_key_root[31] ^= 1;
        ASSERT(device_pairing_host_proposal_root(&replacement, next_proposal));
        ASSERT(memcmp(proposal, next_proposal, 32));
        ASSERT(!db_device_pairing_upgrade_host(&store, &replacement, proposal, root, 150, &publication));
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, observed));
        ASSERT(!memcmp(root, observed, 32));
        ASSERT(db_device_pairing_upgrade_host(&store, &replacement, next_proposal, root, 150, &publication));
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, next_root));
        ASSERT(memcmp(root, next_root, 32));
        ASSERT_EQ(found.paired_at, row.paired_at);
        ASSERT(!db_device_pairing_upgrade_host(&store, &replacement, next_proposal, root, 150, &publication));
        ASSERT(pairing_host_binding_refused(&store, &row, &row.host_scope.binding));
        ASSERT(pairing_host_binding_admitted(&store, &replacement, &replacement.host_scope.binding));
        ASSERT(db_device_pairing_revoke_expected(&store, row.peer_key, 151, next_root, &publication));
        ASSERT(pairing_host_binding_refused(&store, &replacement, &replacement.host_scope.binding));
    } TEST_END
    if (directory[0]) test_rm_rf(directory);
    return failures;
}


static int pairing_host_upgrade_interruptions(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_pairing: interrupted PQ host upgrade cannot admit either authority") {
        for (unsigned stage = 1; stage <= 3; ++stage) {
            ASSERT(test_mkdtemp(directory, sizeof(directory), "device-host-upgrade-int"));
            struct db_device_pairing replacement = pairing_host_row(), row = replacement, found;
            row.capabilities = DEVICE_PAIRING_CAP_STATUS_READ;
            row.host_scope = (struct device_pairing_host_scope){0};
            struct device_pairing_store store;
            uint8_t fingerprint[32], proposal[32], root[32];
            enum device_pairing_publication publication;
            ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
            ASSERT(v2_identity_public_fingerprint(row.peer_key, fingerprint));
            ASSERT(db_device_pairing_insert(&store, &row, fingerprint, &publication));
            ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root));
            ASSERT(device_pairing_host_proposal_root(&replacement, proposal));
            device_pairing_test_interrupt(stage);
            ASSERT(!db_device_pairing_upgrade_host(&store, &replacement, proposal, root, 150, &publication));
            ASSERT_EQ(publication, stage == 1 ? DEVICE_PAIRING_NOT_PUBLISHED : DEVICE_PAIRING_DURABILITY_UNKNOWN);
            ASSERT(!db_device_pairing_find(&store, row.peer_key, &found));
            ASSERT(pairing_host_refused(&store, row.peer_key, 151, DEVICE_PAIRING_HOST_INBOUND, 2222));
            ASSERT(!db_device_pairing_upgrade_host(&store, &replacement, proposal, root, 151, &publication));
            test_rm_rf(directory); directory[0] = 0;
        }
    } TEST_END
    device_pairing_test_interrupt(0);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}


static struct db_device_pairing pairing_psk_row(void)
{
    struct db_device_pairing row = pairing_host_row();
    memset(&row.host_scope.binding, 0, sizeof(row.host_scope.binding));
    row.host_scope.binding.backend_profile = DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK;
    struct device_pairing_psk_binding *binding = &row.host_scope.binding.psk;
    binding->credential_id[0] = 91; binding->key_epoch = 1;
    memcpy(binding->endpoint_a, row.local_key, 32); memcpy(binding->endpoint_b, row.peer_key, 32);
    if (memcmp(binding->endpoint_a, binding->endpoint_b, 32) > 0) {
        memcpy(binding->endpoint_a, row.peer_key, 32); memcpy(binding->endpoint_b, row.local_key, 32);
    }
    return row;
}
static bool pairing_psk_import(struct device_pairing_store *store, struct db_device_pairing *row,
    const uint8_t secret[32], struct device_pairing_psk_publication *report)
{
    uint8_t proposal[32];
    return device_pairing_host_proposal_root(row, proposal) &&
        db_device_pairing_insert_host_psk(store, row, secret, proposal, report);
}
static bool pairing_psk_snapshot(struct device_pairing_store *store,
    const struct db_device_pairing *row, const uint8_t root[32],
    enum device_pairing_host_direction direction, uint16_t port,
    struct device_pairing_psk_snapshot *snapshot)
{
    struct device_pairing_guard guard = {0};
    bool ok = device_pairing_psk_snapshot_acquire(store, row->peer_key, root, 150,
        direction, port, &guard, snapshot);
    bool held = guard.held;
    device_pairing_guard_release(&guard);
    return ok && held;
}
static bool pairing_psk_guard_refused(struct device_pairing_store *store,
    const struct db_device_pairing *row, const uint8_t root[32],
    const struct device_pairing_psk_binding *binding,
    enum device_pairing_host_direction direction, uint16_t port, uint64_t now)
{
    struct device_pairing_guard guard = {0};
    bool ok = device_pairing_guard_acquire_host_psk(store, row->peer_key, root, now,
        binding, direction, port, &guard);
    bool held = guard.held;
    device_pairing_guard_release(&guard);
    return !ok && !held;
}
static bool pairing_psk_path(const char *directory, const uint8_t id[32], char path[1200])
{
    char hex[65]; zcl_hex_encode(id, 32, hex);
    int n = snprintf(path, 1200, "%s/%s.psk", directory, hex);
    return n > 0 && n < 1200;
}
static void pairing_psk_checksum(uint8_t wire[216])
{
    static const uint8_t domain[] = "Z23PSKCREDENTIAL1";
    struct sha3_256_ctx hash;
    sha3_256_init(&hash); sha3_256_write(&hash, domain, sizeof(domain) - 1);
    sha3_256_write(&hash, wire, 184); sha3_256_finalize(&hash, wire + 184);
}
static bool pairing_psk_secret_change(const char *directory, const uint8_t id[32], unsigned offset)
{
    char path[1200]; uint8_t wire[216];
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool ok = pairing_psk_path(directory, id, path) && platform_private_file_open_locked(path, &file) &&
        platform_private_file_read_at(&file, wire, sizeof(wire), 0);
    if (ok) {
        wire[offset] ^= 1; pairing_psk_checksum(wire);
        ok = platform_private_file_write_at(&file, wire, sizeof(wire), 0) && platform_private_file_authority_flush(&file);
    }
    platform_private_file_close(&file);
    memset(wire, 0, sizeof(wire));
    return ok;
}
static int pairing_psk_roundtrip(void)
{
    int failures = 0; char directory[1024] = {0};
    struct device_pairing_psk_snapshot snapshot = {0};
    TEST_CASE("device_pairing PSK: durable immutable secret snapshot and legacy host guard cannot bypass binding") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "pair-psk"));
        struct db_device_pairing row = pairing_psk_row(), found;
        struct device_pairing_store store; uint8_t secret[32] = {17}, root[32], proposal[32];
        struct device_pairing_psk_publication report;
        enum device_pairing_publication publication;
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        ASSERT(device_pairing_host_proposal_root(&row, proposal));
        uint8_t unconfirmed[32] = {0};
        ASSERT(!db_device_pairing_insert_host_psk(&store, &row, secret, unconfirmed, &report));
        ASSERT(!report.mutation_attempted); ASSERT_EQ(report.grant, DEVICE_PAIRING_NOT_PUBLISHED);
        char authority[1200]; ASSERT(snprintf(authority, sizeof(authority), "%s/authority.lock", directory) > 0);
        ASSERT(platform_private_path_absent(authority));
        ASSERT(!db_device_pairing_insert_host(&store, &row, proposal, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
        ASSERT(pairing_psk_import(&store, &row, secret, &report));
        ASSERT_EQ(report.secret, DEVICE_PAIRING_DURABLE); ASSERT_EQ(report.grant, DEVICE_PAIRING_DURABLE);
        ASSERT(report.mutation_attempted); ASSERT(report.intent_retired);
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root));
        ASSERT(pairing_host_binding_refused(&store, &row, &row.host_scope.binding));
        ASSERT(pairing_psk_snapshot(&store, &row, root, DEVICE_PAIRING_HOST_INBOUND, 2222, &snapshot));
        ASSERT(!memcmp(snapshot.secret, secret, 32)); ASSERT(!memcmp(snapshot.root, root, 32));
        ASSERT(pairing_psk_snapshot(&store, &row, root, DEVICE_PAIRING_HOST_OUTBOUND, 3333, &snapshot));
        device_pairing_psk_snapshot_destroy(&snapshot);
        struct device_pairing_psk_snapshot zero = {0}; ASSERT(!memcmp(&snapshot, &zero, sizeof(snapshot)));
        ASSERT(!pairing_psk_import(&store, &row, secret, &report));
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, proposal)); ASSERT(!memcmp(root, proposal, 32));
    } TEST_END
    device_pairing_psk_snapshot_destroy(&snapshot);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}
static int pairing_psk_binding_refusals(void)
{
    int failures = 0; char directory[1024] = {0};
    TEST_CASE("device_pairing PSK: exact current root, credential, epoch, endpoints and directional ports") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "pair-psk-bind"));
        struct db_device_pairing row = pairing_psk_row(), found;
        struct device_pairing_store store; uint8_t secret[32] = {17}, root[32], bad_root[32];
        struct device_pairing_psk_publication report;
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        ASSERT(pairing_psk_import(&store, &row, secret, &report));
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root));
        for (unsigned field = 0; field < 4; ++field) {
            struct device_pairing_psk_binding wrong = row.host_scope.binding.psk;
            switch (field) {
            case 0: wrong.credential_id[0] ^= 1; break;
            case 1: wrong.key_epoch++; break;
            case 2: wrong.endpoint_a[31] ^= 1; break;
            default: wrong.endpoint_b[31] ^= 1; break;
            }
            ASSERT(pairing_psk_guard_refused(&store, &row, root, &wrong, DEVICE_PAIRING_HOST_INBOUND, 2222, 150));
        }
        memcpy(bad_root, root, 32); bad_root[0] ^= 1;
        ASSERT(pairing_psk_guard_refused(&store, &row, bad_root, &row.host_scope.binding.psk, DEVICE_PAIRING_HOST_INBOUND, 2222, 150));
        ASSERT(pairing_psk_guard_refused(&store, &row, root, &row.host_scope.binding.psk, DEVICE_PAIRING_HOST_INBOUND, 3333, 150));
        ASSERT(pairing_psk_guard_refused(&store, &row, root, &row.host_scope.binding.psk, DEVICE_PAIRING_HOST_OUTBOUND, 2222, 150));
        ASSERT(pairing_psk_guard_refused(&store, &row, root, &row.host_scope.binding.psk, DEVICE_PAIRING_HOST_INBOUND, 0, 150));
        ASSERT(pairing_psk_guard_refused(&store, &row, root, &row.host_scope.binding.psk, DEVICE_PAIRING_HOST_INBOUND, 2222, 200));
    } TEST_END
    if (directory[0]) test_rm_rf(directory);
    return failures;
}
static int pairing_psk_secret_refusals(void)
{
    int failures = 0; char directory[1024] = {0};
    struct device_pairing_psk_snapshot snapshot, before;
    memset(&snapshot, 0xa5, sizeof(snapshot)); before = snapshot;
    TEST_CASE("device_pairing PSK: checksum-valid foreign credential metadata cannot release a secret") {
        const unsigned offsets[] = {16, 48, 80, 88, 120};
        for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
            ASSERT(test_mkdtemp(directory, sizeof(directory), "pair-psk-secret"));
            struct db_device_pairing row = pairing_psk_row(), found;
            struct device_pairing_store store; uint8_t secret[32] = {17}, root[32];
            struct device_pairing_psk_publication report;
            ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
            ASSERT(pairing_psk_import(&store, &row, secret, &report));
            ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root));
            ASSERT(pairing_psk_secret_change(directory, row.host_scope.binding.psk.credential_id, offsets[i]));
            ASSERT(!pairing_psk_snapshot(&store, &row, root, DEVICE_PAIRING_HOST_INBOUND, 2222, &snapshot));
            ASSERT(!memcmp(&snapshot, &before, sizeof(snapshot)));
            test_rm_rf(directory); directory[0] = 0;
        }
    } TEST_END
    device_pairing_psk_snapshot_destroy(&snapshot); device_pairing_psk_snapshot_destroy(&before);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}
static int pairing_psk_interruptions(void)
{
    int failures = 0; char directory[1024] = {0};
    struct device_pairing_psk_snapshot snapshot = {0};
    TEST_CASE("device_pairing PSK: single intent blocks interrupted secret/grant publication; late removal is UNKNOWN") {
        for (unsigned stage = 1; stage <= 7; ++stage) {
            ASSERT(test_mkdtemp(directory, sizeof(directory), "pair-psk-int"));
            struct db_device_pairing row = pairing_psk_row(), found;
            struct device_pairing_store store; uint8_t secret[32] = {17}, root[32];
            struct device_pairing_psk_publication report;
            ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
            device_pairing_test_interrupt(stage);
            ASSERT(!pairing_psk_import(&store, &row, secret, &report));
            ASSERT(report.mutation_attempted);
            static const enum device_pairing_publication secret_states[] = {
                DEVICE_PAIRING_NOT_PUBLISHED, DEVICE_PAIRING_NOT_PUBLISHED,
                DEVICE_PAIRING_DURABLE, DEVICE_PAIRING_DURABLE, DEVICE_PAIRING_NOT_PUBLISHED,
                DEVICE_PAIRING_DURABILITY_UNKNOWN, DEVICE_PAIRING_DURABLE, DEVICE_PAIRING_DURABLE};
            ASSERT_EQ(report.secret, secret_states[stage]);
            ASSERT_EQ(report.grant, (stage == 2 || stage == 3 || stage == 7) ?
                DEVICE_PAIRING_DURABILITY_UNKNOWN : DEVICE_PAIRING_NOT_PUBLISHED);
            ASSERT_EQ(report.intent_retired, stage == 7);
            bool observable = db_device_pairing_inspect(&store, row.peer_key, &found, root);
            ASSERT_EQ(observable, stage == 7);
            if (stage == 7) {
                ASSERT_EQ(report.grant, DEVICE_PAIRING_DURABILITY_UNKNOWN);
                ASSERT(pairing_psk_snapshot(&store, &row, root, DEVICE_PAIRING_HOST_INBOUND, 2222, &snapshot));
            } else ASSERT(!report.intent_retired);
            ASSERT(!pairing_psk_import(&store, &row, secret, &report));
            test_rm_rf(directory); directory[0] = 0;
        }
    } TEST_END
    device_pairing_test_interrupt(0); device_pairing_psk_snapshot_destroy(&snapshot);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}
static int pairing_psk_rotation(void)
{
    int failures = 0; char directory[1024] = {0};
    struct device_pairing_guard guard = {0}; struct device_pairing_psk_snapshot snapshot = {0};
    TEST_CASE("device_pairing PSK: exact-root rotation excluded by held snapshot and cannot resurrect revocation") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "pair-psk-rotate"));
        struct db_device_pairing row = pairing_psk_row(), found, next = row;
        struct device_pairing_store store; uint8_t secret[32] = {17}, next_secret[32] = {18}, root[32], next_root[32], proposal[32];
        struct device_pairing_psk_publication report; enum device_pairing_publication publication;
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        ASSERT(pairing_psk_import(&store, &row, secret, &report)); ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root));
        next.host_scope.binding.psk.credential_id[0]++; next.host_scope.binding.psk.key_epoch++;
        ASSERT(device_pairing_host_proposal_root(&next, proposal));
        ASSERT(!db_device_pairing_upgrade_host(&store, &next, proposal, root, 150, &publication));
        struct db_device_pairing invalid = next;
        invalid.host_scope.binding.psk.key_epoch = row.host_scope.binding.psk.key_epoch;
        uint8_t invalid_proposal[32]; ASSERT(device_pairing_host_proposal_root(&invalid, invalid_proposal));
        ASSERT(!db_device_pairing_rotate_host_psk(&store, &invalid, next_secret, invalid_proposal, root, 150, &report));
        invalid = next; memcpy(invalid.host_scope.binding.psk.credential_id, row.host_scope.binding.psk.credential_id, 32);
        ASSERT(device_pairing_host_proposal_root(&invalid, invalid_proposal));
        ASSERT(!db_device_pairing_rotate_host_psk(&store, &invalid, next_secret, invalid_proposal, root, 150, &report));
        ASSERT(!db_device_pairing_rotate_host_psk(&store, &next, next_secret, root, root, 150, &report));
        ASSERT(!db_device_pairing_rotate_host_psk(&store, &next, next_secret, proposal, NULL, 150, &report));
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, next_root)); ASSERT(!memcmp(root, next_root, 32));
        ASSERT(device_pairing_psk_snapshot_acquire(&store, row.peer_key, root, 150, DEVICE_PAIRING_HOST_INBOUND, 2222, &guard, &snapshot));
        bool blocked = !db_device_pairing_rotate_host_psk(&store, &next, next_secret, proposal, root, 150, &report);
        device_pairing_guard_release(&guard); ASSERT(blocked);
        ASSERT(db_device_pairing_rotate_host_psk(&store, &next, next_secret, proposal, root, 150, &report));
        ASSERT_EQ(report.grant, DEVICE_PAIRING_DURABLE);
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, next_root)); ASSERT(memcmp(root, next_root, 32));
        ASSERT_EQ(found.paired_at, row.paired_at);
        ASSERT(!db_device_pairing_rotate_host_psk(&store, &next, next_secret, proposal, root, 150, &report));
        ASSERT(pairing_psk_guard_refused(&store, &row, root, &row.host_scope.binding.psk, DEVICE_PAIRING_HOST_INBOUND, 2222, 150));
        ASSERT(pairing_psk_snapshot(&store, &next, next_root, DEVICE_PAIRING_HOST_INBOUND, 2222, &snapshot));
        ASSERT(!memcmp(snapshot.secret, next_secret, 32));
        char old_path[1200]; ASSERT(pairing_psk_path(directory, row.host_scope.binding.psk.credential_id, old_path)); ASSERT(!platform_private_path_absent(old_path));
        ASSERT(db_device_pairing_revoke_expected(&store, row.peer_key, 151, next_root, &publication));
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root));
        next.host_scope.binding.psk.credential_id[0]++; next.host_scope.binding.psk.key_epoch++;
        ASSERT(device_pairing_host_proposal_root(&next, proposal));
        ASSERT(!db_device_pairing_rotate_host_psk(&store, &next, secret, proposal, root, 152, &report));
    } TEST_END
    device_pairing_guard_release(&guard); device_pairing_psk_snapshot_destroy(&snapshot);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}
static bool pairing_psk_grant_io(const struct device_pairing_store *store,
    const uint8_t peer[32], uint8_t wire[304], bool writing)
{
    char hex[65], path[1200]; zcl_hex_encode(peer, 32, hex);
    int n = snprintf(path, sizeof(path), "%s/%s.grant", store->directory, hex);
    struct platform_private_file file; platform_private_file_init(&file);
    bool ok = n > 0 && (size_t)n < sizeof(path) && platform_private_file_open_locked(path, &file);
    uint64_t length = 0;
    if (ok) ok = platform_private_file_size(&file, &length) && length == 304;
    if (ok) ok = writing ? platform_private_file_write_at(&file, wire, 304, 0) :
        platform_private_file_read_at(&file, wire, 304, 0);
    platform_private_file_close(&file);
    return ok;
}
static void pairing_psk_expected_wire(const struct db_device_pairing *row, uint8_t wire[304])
{
    memset(wire, 0, 304); memcpy(wire, "Z23DEV", 6); wire[6] = 5;
    memcpy(wire + 8, row->profile, 32); memcpy(wire + 40, row->local_key, 32); memcpy(wire + 72, row->peer_key, 32);
    zcl_write_u64_le(wire + 104, row->paired_at); zcl_write_u64_le(wire + 112, row->expires_at);
    zcl_write_u64_le(wire + 120, row->revoked_at); zcl_write_u64_le(wire + 128, row->generation);
    zcl_write_u64_le(wire + 136, row->capabilities);
    wire[144] = (uint8_t)row->host_scope.inbound_port; wire[145] = (uint8_t)(row->host_scope.inbound_port >> 8);
    wire[146] = (uint8_t)row->host_scope.outbound_port; wire[147] = (uint8_t)(row->host_scope.outbound_port >> 8);
    zcl_write_u64_le(wire + 152, 2);
    const struct device_pairing_psk_binding *binding = &row->host_scope.binding.psk;
    memcpy(wire + 160, binding->credential_id, 32); zcl_write_u64_le(wire + 192, binding->key_epoch);
    memcpy(wire + 200, binding->endpoint_a, 32); memcpy(wire + 232, binding->endpoint_b, 32);
    zcl_sha3_256(wire, 272, wire + 272);
}
static void pairing_psk_wire_defect(uint8_t wire[304], unsigned field)
{
    switch (field) {
    case 0: wire[148] = 1; break;
    case 1: wire[156] = 1; break;
    case 2: wire[264] = 1; break;
    case 3: wire[152] = 1; break;
    case 4: wire[6] = 4; break;
    case 5: memset(wire + 160, 0, 32); break;
    case 6: memset(wire + 192, 0, 8); break;
    case 7: wire[200] ^= 1; break;
    default: wire[232] ^= 1; break;
    }
    zcl_sha3_256(wire, 272, wire + 272);
}
static int pairing_psk_wire(void)
{
    int failures = 0; char directory[1024] = {0};
    TEST_CASE("device_pairing PSK: exact v5 bytes/root and checksum-valid malformed encodings refuse") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "pair-psk-wire"));
        struct db_device_pairing row = pairing_psk_row(), found;
        struct device_pairing_store store; uint8_t secret[32] = {17}, root[32], digest[32], wire[304], expected[304], changed[304];
        struct device_pairing_psk_publication report;
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key)); ASSERT(pairing_psk_import(&store, &row, secret, &report));
        ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root)); ASSERT(pairing_psk_grant_io(&store, row.peer_key, wire, false));
        pairing_psk_expected_wire(&row, expected); ASSERT(!memcmp(wire, expected, sizeof(wire)));
        zcl_sha3_256(expected, sizeof(expected), digest); ASSERT(!memcmp(root, digest, 32));
        for (unsigned field = 0; field < 9; ++field) {
            memcpy(changed, wire, sizeof(changed)); pairing_psk_wire_defect(changed, field);
            ASSERT(pairing_psk_grant_io(&store, row.peer_key, changed, true));
            ASSERT(!db_device_pairing_find(&store, row.peer_key, &found));
        }
        ASSERT(pairing_psk_grant_io(&store, row.peer_key, wire, true));
        ASSERT(db_device_pairing_find(&store, row.peer_key, &found));
    } TEST_END
    if (directory[0]) test_rm_rf(directory);
    return failures;
}
static int pairing_psk_one_direction(void)
{
    int failures = 0; char directory[1024] = {0};
    struct device_pairing_psk_snapshot snapshot = {0};
    TEST_CASE("device_pairing PSK: each explicit initiation direction works and zero never grants reverse authority") {
        for (unsigned inbound = 0; inbound < 2; ++inbound) {
            ASSERT(test_mkdtemp(directory, sizeof(directory), "pair-psk-direction"));
            struct db_device_pairing row = pairing_psk_row(), found;
            if (inbound) row.host_scope.outbound_port = 0; else row.host_scope.inbound_port = 0;
            struct device_pairing_store store; uint8_t secret[32] = {17}, root[32]; struct device_pairing_psk_publication report;
            ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key)); ASSERT(pairing_psk_import(&store, &row, secret, &report));
            ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root));
            enum device_pairing_host_direction allowed = inbound ? DEVICE_PAIRING_HOST_INBOUND : DEVICE_PAIRING_HOST_OUTBOUND;
            enum device_pairing_host_direction denied = inbound ? DEVICE_PAIRING_HOST_OUTBOUND : DEVICE_PAIRING_HOST_INBOUND;
            uint16_t port = inbound ? 2222 : 3333;
            ASSERT(pairing_psk_snapshot(&store, &row, root, allowed, port, &snapshot));
            ASSERT(pairing_psk_guard_refused(&store, &row, root, &row.host_scope.binding.psk, denied, port, 150));
            test_rm_rf(directory); directory[0] = 0;
        }
    } TEST_END
    device_pairing_psk_snapshot_destroy(&snapshot);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}
static bool pairing_psk_retire_secret(const char *directory, const uint8_t id[32])
{
    char path[1200]; struct platform_private_file file; platform_private_file_init(&file);
    bool ok = pairing_psk_path(directory, id, path) && platform_private_file_open_locked(path, &file) &&
        platform_private_file_retire(&file, path);
    platform_private_file_close(&file); return ok;
}
static bool pairing_psk_orphan_exact(const char *path)
{
    struct platform_private_file file; platform_private_file_init(&file);
    uint64_t length = 0; char bytes[6];
    bool ok = platform_private_file_open_observation(path, &file) &&
        platform_private_file_size(&file, &length) && length == sizeof(bytes) &&
        platform_private_file_read_at(&file, bytes, sizeof(bytes), 0) && !memcmp(bytes, "orphan", sizeof(bytes));
    platform_private_file_close(&file); return ok;
}
static int pairing_psk_orphan_and_missing(void)
{
    int failures = 0; char directory[1024] = {0};
    struct device_pairing_psk_snapshot snapshot, before; memset(&snapshot, 0xa5, sizeof(snapshot)); before = snapshot;
    TEST_CASE("device_pairing PSK: foreign orphan is never adopted and read never recreates missing secret") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "pair-psk-orphan"));
        struct db_device_pairing row = pairing_psk_row(), found;
        struct device_pairing_store store; uint8_t secret[32] = {17}, root[32]; struct device_pairing_psk_publication report;
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        char path[1200]; ASSERT(pairing_psk_path(directory, row.host_scope.binding.psk.credential_id, path));
        struct platform_private_file file; platform_private_file_init(&file);
        bool orphan = platform_private_file_create(path, &file) && platform_private_file_write_at(&file, "orphan", 6, 0);
        platform_private_file_close(&file); ASSERT(orphan);
        ASSERT(!pairing_psk_import(&store, &row, secret, &report)); ASSERT_EQ(report.grant, DEVICE_PAIRING_NOT_PUBLISHED);
        ASSERT(pairing_psk_orphan_exact(path));
        ASSERT(report.mutation_attempted); ASSERT(!db_device_pairing_find(&store, row.peer_key, &found));
        row.host_scope.binding.psk.credential_id[0]++;
        ASSERT(pairing_psk_import(&store, &row, secret, &report)); ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root));
        ASSERT(pairing_psk_retire_secret(directory, row.host_scope.binding.psk.credential_id));
        ASSERT(!pairing_psk_snapshot(&store, &row, root, DEVICE_PAIRING_HOST_INBOUND, 2222, &snapshot));
        ASSERT(!memcmp(&snapshot, &before, sizeof(snapshot)));
        ASSERT(pairing_psk_path(directory, row.host_scope.binding.psk.credential_id, path)); ASSERT(platform_private_path_absent(path));
    } TEST_END
    device_pairing_psk_snapshot_destroy(&snapshot); device_pairing_psk_snapshot_destroy(&before);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}
static bool pairing_psk_private_defect(const char *directory, const uint8_t id[32], unsigned defect)
{
    char path[1200]; uint8_t wire[216];
    struct platform_private_file file; platform_private_file_init(&file);
    bool ok = pairing_psk_path(directory, id, path) && platform_private_file_open_locked(path, &file) &&
        platform_private_file_read_at(&file, wire, sizeof(wire), 0);
    if (ok) {
        switch (defect) {
        case 0: wire[0] ^= 1; break;
        case 1: wire[9] = 2; break;
        case 2: wire[10] = 1; break;
        case 3: wire[15] ^= 1; break;
        default: break;
        }
        if (defect < 4) pairing_psk_checksum(wire);
        if (defect == 4) wire[184] ^= 1;
        ok = platform_private_file_write_at(&file, wire, sizeof(wire), 0);
        if (ok && defect == 5) ok = platform_private_file_truncate(&file, sizeof(wire) - 1);
        if (ok && defect == 6) {
            const uint8_t trailing = 0;
            ok = platform_private_file_write_at(&file, &trailing, 1, sizeof(wire));
        }
    }
    platform_private_file_close(&file); memory_cleanse(wire, sizeof(wire));
    return ok;
}
static bool pairing_psk_private_observe(const char *directory, const uint8_t id[32],
    uint8_t bytes[217], uint64_t *length)
{
    char path[1200]; struct platform_private_file file; platform_private_file_init(&file);
    bool ok = pairing_psk_path(directory, id, path) && platform_private_file_open_observation(path, &file) &&
        platform_private_file_size(&file, length) && *length <= 217 &&
        platform_private_file_read_at(&file, bytes, (size_t)*length, 0);
    platform_private_file_close(&file); return ok;
}
static int pairing_psk_private_wire_refusals(void)
{
    int failures = 0; char directory[1024] = {0};
    struct device_pairing_psk_snapshot snapshot, before;
    uint8_t prior_bytes[217], observed_bytes[217];
    memset(&snapshot, 0xa5, sizeof(snapshot)); before = snapshot;
    TEST_CASE("device_pairing PSK: private header, checksum and exact file length refuse without secret release or repair") {
        for (unsigned defect = 0; defect < 7; ++defect) {
            ASSERT(test_mkdtemp(directory, sizeof(directory), "pair-psk-private"));
            struct db_device_pairing row = pairing_psk_row(), found;
            struct device_pairing_store store; uint8_t secret[32] = {17}, root[32]; struct device_pairing_psk_publication report;
            ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
            ASSERT(pairing_psk_import(&store, &row, secret, &report));
            ASSERT(db_device_pairing_inspect(&store, row.peer_key, &found, root));
            ASSERT(pairing_psk_private_defect(directory, row.host_scope.binding.psk.credential_id, defect));
            memset(prior_bytes, 0, sizeof(prior_bytes)); memset(observed_bytes, 0, sizeof(observed_bytes));
            uint64_t prior_length = 0, observed_length = 0;
            ASSERT(pairing_psk_private_observe(directory, row.host_scope.binding.psk.credential_id, prior_bytes, &prior_length));
            ASSERT(!pairing_psk_snapshot(&store, &row, root, DEVICE_PAIRING_HOST_INBOUND, 2222, &snapshot));
            ASSERT(!memcmp(&snapshot, &before, sizeof(snapshot)));
            ASSERT(pairing_psk_private_observe(directory, row.host_scope.binding.psk.credential_id, observed_bytes, &observed_length));
            ASSERT_EQ(prior_length, observed_length); ASSERT(!memcmp(prior_bytes, observed_bytes, sizeof(prior_bytes)));
            test_rm_rf(directory); directory[0] = 0;
        }
    } TEST_END
    device_pairing_psk_snapshot_destroy(&snapshot); device_pairing_psk_snapshot_destroy(&before);
    memory_cleanse(prior_bytes, sizeof(prior_bytes)); memory_cleanse(observed_bytes, sizeof(observed_bytes));
    if (directory[0]) test_rm_rf(directory);
    return failures;
}
/* Cached tunnel-authority revalidation: every case asserts through the process
 * counters that the change forced a full acquisition (or a refusal) and never
 * a cache hit, because a replaced-but-valid file still acquires successfully. */
struct pairing_cache_fixture {
    char directory[1024], lock[1200], grant[1200], pending[1240];
    struct db_device_pairing row; struct device_pairing_store store; uint8_t root[32];
    struct device_pairing_guard_cache cache;
};
static bool pairing_cache_acquire(struct pairing_cache_fixture *f, struct device_pairing_guard *guard)
{
    return device_pairing_guard_acquire_host_psk_cached(&f->store, f->row.peer_key, f->root, 150,
        &f->row.host_scope.binding.psk, DEVICE_PAIRING_HOST_INBOUND, 2222, &f->cache, guard);
}
static bool pairing_cache_open(struct pairing_cache_fixture *f, const char *name)
{
    memset(f, 0, sizeof(*f));
    struct device_pairing_psk_publication report; uint8_t secret[32] = {17}; struct db_device_pairing found;
    char hex[65];
    if (!test_mkdtemp(f->directory, sizeof(f->directory), name)) return false;
    f->row = pairing_psk_row();
    if (!device_pairing_store_open(&f->store, f->directory, f->row.profile, f->row.local_key) ||
        !pairing_psk_import(&f->store, &f->row, secret, &report) ||
        !db_device_pairing_inspect(&f->store, f->row.peer_key, &found, f->root)) return false;
    zcl_hex_encode(f->row.peer_key, 32, hex);
    return snprintf(f->lock, sizeof(f->lock), "%s/authority.lock", f->store.directory) > 0 &&
        snprintf(f->grant, sizeof(f->grant), "%s/%s.grant", f->store.directory, hex) > 0 &&
        snprintf(f->pending, sizeof(f->pending), "%s.pending", f->grant) > 0;
}
/* Acquire and release once so the memo is primed, then once more to prove a hit. */
static bool pairing_cache_prime(struct pairing_cache_fixture *f)
{
    struct device_pairing_guard guard = {0}; uint64_t full0, hit0, full1, hit1;
    device_pairing_test_guard_counts(&full0, &hit0);
    bool ok = pairing_cache_acquire(f, &guard); device_pairing_guard_release(&guard);
    ok = ok && pairing_cache_acquire(f, &guard); device_pairing_guard_release(&guard);
    device_pairing_test_guard_counts(&full1, &hit1);
    return ok && full1 == full0 + 1 && hit1 == hit0 + 1;
}
/* Copies path's bytes to a fresh file and renames it over path: new inode, same bytes. */
static bool pairing_cache_replace(const char *path)
{
    char copy[1300]; uint8_t bytes[512]; if (snprintf(copy, sizeof(copy), "%s.copy", path) < 0) return false;
    FILE *in = fopen(path, "rb"); if (!in) return false;
    size_t length = fread(bytes, 1, sizeof(bytes), in); fclose(in);
    struct platform_private_file file; platform_private_file_init(&file);
    bool ok = platform_private_file_create(copy, &file) &&
        (!length || platform_private_file_write_at(&file, bytes, length, 0));
    platform_private_file_close(&file);
    return ok && rename(copy, path) == 0;
}
/* After a full acquisition re-memoized, the very next check must be a hit again. */
static bool pairing_cache_hits(struct pairing_cache_fixture *f)
{
    struct device_pairing_guard guard = {0}; uint64_t full0, hit0, full1, hit1;
    device_pairing_test_guard_counts(&full0, &hit0);
    bool ok = pairing_cache_acquire(f, &guard); device_pairing_guard_release(&guard);
    device_pairing_test_guard_counts(&full1, &hit1);
    return ok && full1 == full0 && hit1 == hit0 + 1;
}
static int pairing_cache_case1(void)
{
    int failures = 0; struct pairing_cache_fixture f = {0}; struct device_pairing_guard guard = {0}, second = {0};
    uint64_t full0, hit0, full1, hit1; enum device_pairing_publication publication;
    (void)second; (void)full0; (void)hit0; (void)full1; (void)hit1; (void)publication;
    TEST_CASE("device_pairing cache: hit holds the shared lock until release, a second borrower takes the full path") {
        ASSERT(pairing_cache_open(&f, "pair-cache-hit")); ASSERT(pairing_cache_prime(&f));
        ASSERT(pairing_cache_acquire(&f, &guard));
        ASSERT(!db_device_pairing_revoke(&f.store, f.row.peer_key, 160, &publication));
        device_pairing_test_guard_counts(&full0, &hit0);
        ASSERT(pairing_cache_acquire(&f, &second));
        device_pairing_test_guard_counts(&full1, &hit1);
        ASSERT_EQ(full1, full0 + 1); ASSERT_EQ(hit1, hit0);
        device_pairing_guard_release(&second);
        ASSERT(!db_device_pairing_revoke(&f.store, f.row.peer_key, 160, &publication));
        device_pairing_guard_release(&guard);
        device_pairing_guard_cache_destroy(&f.cache);
        ASSERT(db_device_pairing_revoke(&f.store, f.row.peer_key, 160, &publication));
    } TEST_END
    if (f.directory[0]) test_rm_rf(f.directory);
    return failures;
}
static int pairing_cache_case2(void)
{
    int failures = 0; struct pairing_cache_fixture f = {0}; struct device_pairing_guard guard = {0}, second = {0};
    uint64_t full0, hit0, full1, hit1; enum device_pairing_publication publication;
    (void)second; (void)full0; (void)hit0; (void)full1; (void)hit1; (void)publication;
    TEST_CASE("device_pairing cache: destroying the memo under an outstanding guard keeps the lock until release") {
        ASSERT(pairing_cache_open(&f, "pair-cache-destroy")); ASSERT(pairing_cache_prime(&f));
        ASSERT(pairing_cache_acquire(&f, &guard)); device_pairing_guard_cache_destroy(&f.cache);
        ASSERT(!db_device_pairing_revoke(&f.store, f.row.peer_key, 160, &publication));
        device_pairing_guard_release(&guard);
        ASSERT(db_device_pairing_revoke(&f.store, f.row.peer_key, 160, &publication));
    } TEST_END
    if (f.directory[0]) test_rm_rf(f.directory);
    return failures;
}
static int pairing_cache_case3(void)
{
    int failures = 0; struct pairing_cache_fixture f = {0}; struct device_pairing_guard guard = {0}, second = {0};
    uint64_t full0, hit0, full1, hit1; enum device_pairing_publication publication;
    (void)second; (void)full0; (void)hit0; (void)full1; (void)hit1; (void)publication;
    TEST_CASE("device_pairing cache: lock file replaced by a new inode is seen by the next check") {
        ASSERT(pairing_cache_open(&f, "pair-cache-lock")); ASSERT(pairing_cache_prime(&f));
        ASSERT(pairing_cache_replace(f.lock));
        device_pairing_test_guard_counts(&full0, &hit0);
        ASSERT(pairing_cache_acquire(&f, &guard)); device_pairing_guard_release(&guard);
        device_pairing_test_guard_counts(&full1, &hit1);
        ASSERT_EQ(full1, full0 + 1); ASSERT_EQ(hit1, hit0);
        ASSERT(pairing_cache_hits(&f)); device_pairing_guard_cache_destroy(&f.cache);
    } TEST_END
    if (f.directory[0]) test_rm_rf(f.directory);
    return failures;
}
static int pairing_cache_case4(void)
{
    int failures = 0; struct pairing_cache_fixture f = {0}; struct device_pairing_guard guard = {0}, second = {0};
    uint64_t full0, hit0, full1, hit1; enum device_pairing_publication publication;
    (void)second; (void)full0; (void)hit0; (void)full1; (void)hit1; (void)publication;
    TEST_CASE("device_pairing cache: grant replaced with identical bytes revalidates through the full path") {
        ASSERT(pairing_cache_open(&f, "pair-cache-grant")); ASSERT(pairing_cache_prime(&f));
        ASSERT(pairing_cache_replace(f.grant));
        device_pairing_test_guard_counts(&full0, &hit0);
        ASSERT(pairing_cache_acquire(&f, &guard));
        ASSERT(!memcmp(guard.root, f.root, 32)); device_pairing_guard_release(&guard);
        device_pairing_test_guard_counts(&full1, &hit1);
        ASSERT_EQ(full1, full0 + 1); ASSERT_EQ(hit1, hit0);
        ASSERT(pairing_cache_hits(&f)); device_pairing_guard_cache_destroy(&f.cache);
    } TEST_END
    if (f.directory[0]) test_rm_rf(f.directory);
    return failures;
}
static int pairing_cache_case5(void)
{
    int failures = 0; struct pairing_cache_fixture f = {0}; struct device_pairing_guard guard = {0}, second = {0};
    uint64_t full0, hit0, full1, hit1; enum device_pairing_publication publication;
    (void)second; (void)full0; (void)hit0; (void)full1; (void)hit1; (void)publication;
    TEST_CASE("device_pairing cache: a pending intent created between checks refuses and never hits") {
        ASSERT(pairing_cache_open(&f, "pair-cache-pending")); ASSERT(pairing_cache_prime(&f));
        struct platform_private_file intent; platform_private_file_init(&intent);
        ASSERT(platform_private_file_create(f.pending, &intent)); platform_private_file_close(&intent);
        device_pairing_test_guard_counts(&full0, &hit0);
        ASSERT(!pairing_cache_acquire(&f, &guard));
        device_pairing_test_guard_counts(&full1, &hit1);
        ASSERT_EQ(hit1, hit0); ASSERT(!guard.held);
        ASSERT_EQ(remove(f.pending), 0);
        ASSERT(pairing_cache_acquire(&f, &guard)); device_pairing_guard_release(&guard);
        device_pairing_guard_cache_destroy(&f.cache);
    } TEST_END
    if (f.directory[0]) test_rm_rf(f.directory);
    return failures;
}
static int pairing_cache_case6(void)
{
    int failures = 0; struct pairing_cache_fixture f = {0}; struct device_pairing_guard guard = {0}, second = {0};
    uint64_t full0, hit0, full1, hit1; enum device_pairing_publication publication;
    (void)second; (void)full0; (void)hit0; (void)full1; (void)hit1; (void)publication;
    TEST_CASE("device_pairing cache: a revoke that completed before the check is observed") {
        ASSERT(pairing_cache_open(&f, "pair-cache-revoke")); ASSERT(pairing_cache_prime(&f));
        ASSERT(db_device_pairing_revoke(&f.store, f.row.peer_key, 160, &publication));
        ASSERT(!pairing_cache_acquire(&f, &guard)); ASSERT(!guard.held);
        device_pairing_guard_cache_destroy(&f.cache);
    } TEST_END
    if (f.directory[0]) test_rm_rf(f.directory);
    return failures;
}
static int pairing_cache_revalidation(void)
{
    return pairing_cache_case1() + pairing_cache_case2() + pairing_cache_case3() + pairing_cache_case4() + pairing_cache_case5() + pairing_cache_case6();
}
#else
static bool pairing_windows_no_psk_files(const char *directory, const uint8_t id[32])
{
    char hex[65], path[1200]; zcl_hex_encode(id, 32, hex);
    const char *suffixes[] = {"psk", "psk.staging"};
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); ++i) {
        int n = snprintf(path, sizeof(path), "%s/%s.%s", directory, hex, suffixes[i]);
        if (n <= 0 || (size_t)n >= sizeof(path) || !platform_private_path_absent(path)) return false;
    }
    return true;
}
static bool pairing_windows_no_files(const char *directory, const uint8_t peer[32])
{
    char hex[65], path[1200];
    zcl_hex_encode(peer, 32, hex);
    int n = snprintf(path, sizeof(path), "%s/authority.lock", directory);
    if (n <= 0 || (size_t)n >= sizeof(path) || !platform_private_path_absent(path)) return false;
    const char *suffixes[] = {"grant", "grant.pending", "grant.staging"};
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); ++i) {
        n = snprintf(path, sizeof(path), "%s/%s.%s", directory, hex, suffixes[i]);
        if (n <= 0 || (size_t)n >= sizeof(path) || !platform_private_path_absent(path)) return false;
    }
    return true;
}
static int pairing_windows_mutations_refused(void)
{
    int failures = 0;
    char directory[1024] = {0};
    TEST_CASE("device_pairing: Windows unsupported durability refuses all grant mutations before file access") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-windows-refusal"));
        struct db_device_pairing row = {.profile = {1}, .local_key = {2},
            .peer_key = {3}, .paired_at = 100, .expires_at = 200,
            .capabilities = DEVICE_PAIRING_CAP_STATUS_READ};
        struct device_pairing_store store;
        uint8_t fingerprint[32], expected[32] = {9};
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        ASSERT(v2_identity_public_fingerprint(row.peer_key, fingerprint));
        enum device_pairing_publication publication = DEVICE_PAIRING_DURABLE;
        ASSERT(!db_device_pairing_insert(&store, &row, fingerprint, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
        ASSERT(pairing_windows_no_files(directory, row.peer_key));
        publication = DEVICE_PAIRING_DURABLE;
        ASSERT(!db_device_pairing_upgrade(&store, &row, fingerprint, expected, 150, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
        ASSERT(pairing_windows_no_files(directory, row.peer_key));
        publication = DEVICE_PAIRING_DURABLE;
        ASSERT(!db_device_pairing_revoke(&store, row.peer_key, 150, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
        ASSERT(pairing_windows_no_files(directory, row.peer_key));
        publication = DEVICE_PAIRING_DURABLE;
        ASSERT(!db_device_pairing_revoke_expected(&store, row.peer_key, 150, expected, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
        ASSERT(pairing_windows_no_files(directory, row.peer_key));
        ASSERT_EQ(row.revoked_at, 0);
        ASSERT_EQ(row.generation, 0);
        row.capabilities = DEVICE_PAIRING_CAP_HOST_FORWARD;
        row.host_scope.inbound_port = 2222;
        row.host_scope.binding.backend_profile = DEVICE_PAIRING_HOST_OPENSSH_MLKEM768X25519_MLDSA44ED25519;
        row.host_scope.binding.local_pq_key_root[0] = 4;
        row.host_scope.binding.peer_pq_key_root[0] = 5;
        ASSERT(device_pairing_host_proposal_root(&row, fingerprint));
        ASSERT(!db_device_pairing_insert_host(&store, &row, fingerprint, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
        ASSERT(pairing_windows_no_files(directory, row.peer_key));
        ASSERT(!db_device_pairing_upgrade_host(&store, &row, fingerprint, expected, 150, &publication));
        ASSERT_EQ(publication, DEVICE_PAIRING_NOT_PUBLISHED);
        ASSERT(pairing_windows_no_files(directory, row.peer_key));
        memset(&row.host_scope.binding, 0, sizeof(row.host_scope.binding));
        row.host_scope.binding.backend_profile = DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK;
        row.host_scope.binding.psk.credential_id[0] = 91; row.host_scope.binding.psk.key_epoch = 1;
        memcpy(row.host_scope.binding.psk.endpoint_a, row.local_key, 32);
        memcpy(row.host_scope.binding.psk.endpoint_b, row.peer_key, 32);
        uint8_t secret[32] = {17}; struct device_pairing_psk_publication report;
        ASSERT(device_pairing_host_proposal_root(&row, fingerprint));
        ASSERT(!db_device_pairing_insert_host_psk(&store, &row, secret, fingerprint, &report));
        ASSERT(!report.mutation_attempted); ASSERT_EQ(report.secret, DEVICE_PAIRING_NOT_PUBLISHED);
        ASSERT_EQ(report.grant, DEVICE_PAIRING_NOT_PUBLISHED); ASSERT(pairing_windows_no_files(directory, row.peer_key));
        ASSERT(pairing_windows_no_psk_files(directory, row.host_scope.binding.psk.credential_id));
        ASSERT(!db_device_pairing_rotate_host_psk(&store, &row, secret, fingerprint, expected, 150, &report));
        ASSERT(!report.mutation_attempted); ASSERT(pairing_windows_no_files(directory, row.peer_key));
        ASSERT(pairing_windows_no_psk_files(directory, row.host_scope.binding.psk.credential_id));
    } TEST_END
    if (directory[0]) test_rm_rf(directory);
    return failures;
}
#endif
int test_device_pairing(void);
int test_device_pairing(void)
{
#if defined(_WIN32)
    return pairing_windows_mutations_refused();
#else
    return pairing_legacy_capability() + pairing_capability_rows() +
        pairing_capability_corruption() + pairing_lifecycle() +
        pairing_corruption() + pairing_publication_interruptions(false) +
        pairing_publication_interruptions(true) + pairing_bind_validation() +
        pairing_bind_wire_refusals() + pairing_bind_roundtrip() +
        pairing_inspection_roots() + pairing_upgrade_refusals() +
        pairing_upgrade_publication() + pairing_expected_revoke() +
        pairing_host_validation() + pairing_host_directions() + pairing_host_wire() + pairing_host_upgrade() +
        pairing_host_interruptions() + pairing_host_confirmations() + pairing_host_rotation() +
        pairing_host_upgrade_interruptions() + pairing_psk_roundtrip() +
        pairing_psk_binding_refusals() + pairing_psk_secret_refusals() +
        pairing_psk_interruptions() + pairing_psk_rotation() + pairing_psk_wire() +
        pairing_psk_one_direction() + pairing_psk_orphan_and_missing() +
        pairing_psk_private_wire_refusals() + pairing_cache_revalidation();
#endif
}
