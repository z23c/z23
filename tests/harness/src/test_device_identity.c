/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: trusted private-profile initialization and read-only qualification. */
#include "test/test_core.h"
#include "services/device_identity.h"
#include "models/device_profile.h"
#include "platform/private_file.h"
#include "support/cleanse.h"
#include "platform/positioned_file.h"
#include "sha3/sha3.h"
#include <stddef.h>
#include <stdio.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif
#include <string.h>

struct identity_fixture {
    char base[1024], profile[1200];
    struct device_identity identity;
    struct platform_private_file file;
};
static void fixture_init(struct identity_fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    platform_private_file_init(&fixture->file);
}
static void fixture_close(struct identity_fixture *fixture)
{
    device_identity_test_interrupt(0);
    platform_private_file_close(&fixture->file);
    device_identity_close(&fixture->identity);
    if (fixture->base[0]) test_rm_rf(fixture->base);
}
static bool fixture_directory(struct identity_fixture *fixture)
{
    if (!test_mkdtemp(fixture->base, sizeof(fixture->base), "device-identity")) return false;
    int n = snprintf(fixture->profile, sizeof(fixture->profile), "%s/profile", fixture->base);
    return n > 0 && (size_t)n < sizeof(fixture->profile);
}
static bool identity_erased(const struct device_identity *identity)
{
    const uint8_t *bytes = (const uint8_t *)identity;
    uint8_t bits = 0;
    for (size_t i = 0; i < sizeof(*identity); ++i) bits |= bytes[i];
    return bits == 0;
}
#if !defined(_WIN32)
static bool fixture_file(struct identity_fixture *fixture, const char *leaf,
                          char path[1300])
{
    int n = snprintf(path, 1300, "%s/%s", fixture->profile, leaf);
    return n > 0 && n < 1300 && platform_private_file_open_locked(path, &fixture->file);
}

static int identity_create_and_reopen(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: durable initialization, observed reopen and create-only refusal") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        ASSERT(device_identity_open(&fixture.identity, fixture.profile, true, &report).ok);
        ASSERT_EQ(report.state, DEVICE_IDENTITY_DURABLE);
        ASSERT(report.public_key_known);
        ASSERT(!memcmp(report.public_key, fixture.identity.public_key, 32));
        uint8_t expected[32];
        memcpy(expected, report.public_key, 32);
        device_identity_close(&fixture.identity);
        ASSERT(identity_erased(&fixture.identity));
        ASSERT(device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT_EQ(report.state, DEVICE_IDENTITY_NOT_PUBLISHED);
        ASSERT(!memcmp(expected, fixture.identity.public_key, 32));
        struct zcl_result retry = device_identity_open(&fixture.identity, fixture.profile, true, &report);
        ASSERT(!retry.ok);
        ASSERT_EQ(report.state, DEVICE_IDENTITY_NOT_PUBLISHED);
        ASSERT(identity_erased(&fixture.identity));
        ASSERT(device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT(!memcmp(expected, fixture.identity.public_key, 32));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static int identity_interrupted(unsigned stage)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: interrupted initialization preserves public facts, not secret output") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        memset(&fixture.identity, 0xa5, sizeof(fixture.identity));
        device_identity_test_interrupt(stage);
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, true, &report).ok);
        ASSERT_EQ(report.state, DEVICE_IDENTITY_DURABILITY_UNKNOWN);
        ASSERT_EQ(report.public_key_known, stage != 1);
        ASSERT(identity_erased(&fixture.identity));
        uint8_t expected[32];
        memcpy(expected, report.public_key, 32);
        char pending[1300];
        int n = snprintf(pending, sizeof(pending), "%s/%s", fixture.profile, DEVICE_PROFILE_PENDING);
        ASSERT(n > 0);
        ASSERT((size_t)n < sizeof(pending));
        ASSERT_EQ(platform_private_path_absent(pending), stage == 3);
        struct device_identity_publication_report observed;
        struct zcl_result read = device_identity_open(&fixture.identity, fixture.profile, false, &observed);
        ASSERT_EQ(read.ok, stage == 3);
        ASSERT_EQ(observed.state, DEVICE_IDENTITY_NOT_PUBLISHED);
        if (stage == 3) ASSERT(!memcmp(expected, observed.public_key, 32));
        else ASSERT(identity_erased(&fixture.identity));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static int identity_foreign_directory(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: foreign directory stays untouched and invalid arguments erase prior secrets") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        ASSERT(!device_identity_open(&fixture.identity, fixture.base, true, &report).ok);
        ASSERT_EQ(report.state, DEVICE_IDENTITY_NOT_PUBLISHED);
        char key[1300];
        int n = snprintf(key, sizeof(key), "%s/v2_identity.key", fixture.base);
        ASSERT(n > 0);
        ASSERT((size_t)n < sizeof(key));
        ASSERT(platform_private_path_absent(key));
        memset(&fixture.identity, 0xa5, sizeof(fixture.identity));
        ASSERT(!device_identity_open(&fixture.identity, NULL, false, &report).ok);
        ASSERT(identity_erased(&fixture.identity));
        ASSERT(!report.public_key_known);
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT(platform_private_path_absent(fixture.profile));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static int identity_profile_refusals(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: profile publication never replaces and zero or changed bytes refuse reads") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        ASSERT(device_identity_open(&fixture.identity, fixture.profile, true, &report).ok);
        uint8_t expected[32], wrong[32] = {9}, observed[32];
        memcpy(expected, report.public_key, 32);
        ASSERT(!db_device_profile_publish(fixture.profile, wrong));
        ASSERT(db_device_profile_read(fixture.profile, observed));
        ASSERT(!memcmp(expected, observed, 32));
        char path[1300];
        ASSERT(fixture_file(&fixture, "owner-device.profile", path));
        uint8_t zero[32] = {0};
        ASSERT(platform_private_file_write_at(&fixture.file, zero, 32, 8));
        platform_private_file_close(&fixture.file);
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT(identity_erased(&fixture.identity));
        ASSERT(fixture_file(&fixture, "owner-device.profile", path));
        ASSERT(platform_private_file_write_at(&fixture.file, wrong, 32, 8));
        platform_private_file_close(&fixture.file);
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT(identity_erased(&fixture.identity));
        ASSERT(fixture_file(&fixture, "owner-device.profile", path));
        uint8_t extra = 1;
        ASSERT(platform_private_file_write_at(&fixture.file, &extra, 1, 40));
        platform_private_file_close(&fixture.file);
        ASSERT(!db_device_profile_read(fixture.profile, observed));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static int identity_missing_key(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: missing key is never recreated by read or initialization retry") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        ASSERT(device_identity_open(&fixture.identity, fixture.profile, true, &report).ok);
        char path[1300];
        ASSERT(fixture_file(&fixture, "v2_identity.key", path));
        ASSERT(platform_private_file_retire(&fixture.file, path));
        platform_private_file_close(&fixture.file);
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT(platform_private_path_absent(path));
        ASSERT(identity_erased(&fixture.identity));
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, true, &report).ok);
        ASSERT(platform_private_path_absent(path));
        ASSERT(identity_erased(&fixture.identity));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

/* Mutation-sweep additions: descriptors, one-shot fault, intent bytes, refusal codes,
 * the pairing profile known answer and the full-width public key comparison. */
static int lowest_free_fd(void)
{
    int fd = open("/dev/null", O_RDONLY);
    if (fd >= 0) close(fd);
    return fd;
}

static bool profile_path_n(const struct identity_fixture *fixture, const char *name,
                           char path[1300])
{
    int n = snprintf(path, 1300, "%s/%s", fixture->base, name);
    return n > 0 && n < 1300;
}

static int identity_descriptor_hygiene(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: open, create and reopen release every descriptor they take") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        int before = lowest_free_fd();
        ASSERT(before >= 0);
        for (int i = 0; i < 6; ++i) {
            char name[16], path[1300];
            snprintf(name, sizeof(name), "c%d", i);
            ASSERT(profile_path_n(&fixture, name, path));
            ASSERT(device_identity_open(&fixture.identity, path, true, &report).ok);
        }
        int created = lowest_free_fd();
        ASSERT(created >= 0 && created < before + 3);
        for (int i = 0; i < 16; ++i)
            ASSERT(device_identity_open(&fixture.identity, fixture.base, false, &report).ok == false);
        char first[1300];
        ASSERT(profile_path_n(&fixture, "c0", first));
        for (int i = 0; i < 16; ++i)
            ASSERT(device_identity_open(&fixture.identity, first, false, &report).ok);
        int after = lowest_free_fd();
        ASSERT(after >= 0 && after < before + 8);
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static bool read_pending(const char *profile, uint8_t out[40], uint64_t *size)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snap;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open_beneath(&file, profile, DEVICE_PROFILE_PENDING) &&
        platform_positioned_file_snapshot(&file, &snap) && snap.size <= 40 &&
        platform_positioned_file_read(&file, out, (size_t)snap.size, 0) == (int64_t)snap.size;
    platform_positioned_file_close(&file);
    if (ok) *size = snap.size;
    return ok;
}

static int identity_interrupt_one_shot(unsigned stage)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: an injected interruption fires once and leaves the exact intent bytes") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        device_identity_test_interrupt(stage);
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, true, &report).ok);
        if (stage != 3) {
            static const uint8_t intent[] = "zcl.owner-device.initializing.v1";
            uint8_t bytes[40] = {0};
            uint64_t size = 0;
            ASSERT(read_pending(fixture.profile, bytes, &size));
            ASSERT_EQ(size, (uint64_t)sizeof(intent));
            ASSERT(!memcmp(bytes, intent, sizeof(intent)));
        }
        char second[1300];
        ASSERT(profile_path_n(&fixture, "second", second));
        ASSERT(device_identity_open(&fixture.identity, second, true, &report).ok);
        ASSERT_EQ(report.state, DEVICE_IDENTITY_DURABLE);
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static bool tail_is_clean(const struct device_identity *identity)
{
    size_t len = strlen(identity->directory);
    if (len < 8 || strcmp(identity->directory + len - 8, "/profile")) return false;
    for (size_t i = len + 1; i < sizeof(identity->directory); ++i)
        if (identity->directory[i]) return false;
    return true;
}

static bool report_padding_clear(const struct device_identity_publication_report *report)
{
    size_t end = offsetof(struct device_identity_publication_report, public_key) + 32;
    const uint8_t *bytes = (const uint8_t *)report;
    for (size_t i = end; i < sizeof(*report); ++i)
        if (bytes[i]) return false;
    return true;
}

static int identity_open_outputs(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: open records its resolved directory and writes only the report key") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        ASSERT(device_identity_open(&fixture.identity, fixture.profile, true, &report).ok);
        ASSERT(tail_is_clean(&fixture.identity));
        ASSERT(report_padding_clear(&report));
        ASSERT(device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT(tail_is_clean(&fixture.identity));
        ASSERT(report_padding_clear(&report));
        ASSERT(report.public_key_known);
        ASSERT(!memcmp(report.public_key, fixture.identity.public_key, 32));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static int identity_refusal_codes(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: unresolvable, absent and malformed requests refuse with code 1") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        char orphan[1300], parent[1300];
        ASSERT(profile_path_n(&fixture, "missing", parent));
        int n = snprintf(orphan, sizeof(orphan), "%s/profile", parent);
        ASSERT(n > 0 && (size_t)n < sizeof(orphan));
        struct zcl_result r = device_identity_open(&fixture.identity, orphan, true, &report);
        ASSERT(!r.ok);
        ASSERT_EQ(r.code, 1);
        ASSERT(identity_erased(&fixture.identity));
        ASSERT(platform_private_path_absent(parent));
        r = device_identity_open(&fixture.identity, orphan, false, &report);
        ASSERT(!r.ok);
        ASSERT_EQ(r.code, 1);
        r = device_identity_open(&fixture.identity, fixture.profile, false, &report);
        ASSERT(!r.ok);
        ASSERT_EQ(r.code, 1);
        r = device_identity_open(&fixture.identity, NULL, false, &report);
        ASSERT_EQ(r.code, 1);
        r = device_identity_open(&fixture.identity, "", false, &report);
        ASSERT_EQ(r.code, 1);
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static bool expected_pair_profile(const uint8_t a[32], const uint8_t b[32], uint8_t out[32])
{
    static const char domain[] = "zcl.owner-device.profile.v1";
    uint8_t msg[sizeof(domain) - 1 + 64];
    const uint8_t *lo = memcmp(a, b, 32) < 0 ? a : b;
    const uint8_t *hi = lo == a ? b : a;
    memcpy(msg, domain, sizeof(domain) - 1);
    memcpy(msg + sizeof(domain) - 1, lo, 32);
    memcpy(msg + sizeof(domain) - 1 + 32, hi, 32);
    sha3_256(msg, sizeof(msg), out);
    return true;
}

static bool pair_matches(const struct device_identity *identity, const uint8_t peer[32])
{
    struct device_pairing_store store;
    uint8_t expected[32];
    memset(&store, 0, sizeof(store));
    expected_pair_profile(identity->public_key, peer, expected);
    struct zcl_result r = device_identity_pair_store(identity, peer, &store);
    return r.ok && !memcmp(store.profile, expected, 32) &&
        !memcmp(store.local_key, identity->public_key, 32) &&
        !strcmp(store.directory, identity->directory);
}

static int identity_pair_store_profile(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: pairing profile is SHA3-256 of domain and the ordered key pair") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        ASSERT(device_identity_open(&fixture.identity, fixture.profile, true, &report).ok);
        const uint8_t *own = fixture.identity.public_key;
        uint8_t peer[32];
        memcpy(peer, own, 32);
        peer[31] = 0xff;
        ASSERT(pair_matches(&fixture.identity, peer));
        peer[31] = 0x00;
        ASSERT(pair_matches(&fixture.identity, peer));
        memcpy(peer, own, 32);
        peer[0] = (uint8_t)(own[0] + 1);
        ASSERT(pair_matches(&fixture.identity, peer));
        peer[0] = (uint8_t)(own[0] - 1);
        ASSERT(pair_matches(&fixture.identity, peer));
        memset(peer, 0x5a, 32);
        ASSERT(pair_matches(&fixture.identity, peer));
        memset(peer, 0xff, 32);
        ASSERT(pair_matches(&fixture.identity, peer));
        memset(peer, 0x00, 32);
        peer[31] = 1;
        ASSERT(pair_matches(&fixture.identity, peer));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static int identity_pair_store_refusals(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: pairing refuses missing arguments and an unavailable profile with code 1") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        ASSERT(device_identity_open(&fixture.identity, fixture.profile, true, &report).ok);
        uint8_t peer[32];
        memset(peer, 0x33, 32);
        struct device_pairing_store store;
        struct zcl_result r = device_identity_pair_store(NULL, peer, &store);
        ASSERT(!r.ok);
        ASSERT_EQ(r.code, 1);
        r = device_identity_pair_store(&fixture.identity, NULL, &store);
        ASSERT(!r.ok);
        ASSERT_EQ(r.code, 1);
        r = device_identity_pair_store(&fixture.identity, peer, NULL);
        ASSERT(!r.ok);
        ASSERT_EQ(r.code, 1);
        struct device_identity stranded;
        memset(&stranded, 0, sizeof(stranded));
        memset(stranded.public_key, 0x11, 32);
        r = device_identity_pair_store(&stranded, peer, &store);
        ASSERT(!r.ok);
        ASSERT_EQ(r.code, 1);
        device_identity_close(&stranded);
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static int identity_public_key_full_width(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: a profile differing only in the last key byte refuses the read") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        ASSERT(device_identity_open(&fixture.identity, fixture.profile, true, &report).ok);
        uint8_t last = (uint8_t)(report.public_key[31] ^ 1);
        char path[1300];
        ASSERT(fixture_file(&fixture, "owner-device.profile", path));
        ASSERT(platform_private_file_write_at(&fixture.file, &last, 1, 39));
        platform_private_file_close(&fixture.file);
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT(identity_erased(&fixture.identity));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}

static int identity_sweep_cases(void)
{
    return identity_descriptor_hygiene() + identity_interrupt_one_shot(1) +
        identity_interrupt_one_shot(2) + identity_interrupt_one_shot(3) +
        identity_open_outputs() + identity_refusal_codes() +
        identity_pair_store_profile() + identity_pair_store_refusals() +
        identity_public_key_full_width();
}
#else
static int identity_windows_creation_refused(void)
{
    int failures = 0;
    struct identity_fixture fixture;
    fixture_init(&fixture);
    TEST_CASE("device_identity: Windows unsupported durability refuses creation without files or secret output") {
        ASSERT(fixture_directory(&fixture));
        struct device_identity_publication_report report;
        memset(&fixture.identity, 0xa5, sizeof(fixture.identity));
        struct zcl_result result = device_identity_open(&fixture.identity, fixture.profile, true, &report);
        ASSERT(!result.ok);
        ASSERT(strstr(result.message, "unsupported") != NULL);
        ASSERT_EQ(report.state, DEVICE_IDENTITY_NOT_PUBLISHED);
        ASSERT(!report.public_key_known);
        ASSERT(identity_erased(&fixture.identity));
        ASSERT(platform_private_path_absent(fixture.profile));
        ASSERT(!device_identity_open(&fixture.identity, fixture.profile, false, &report).ok);
        ASSERT(platform_private_path_absent(fixture.profile));
        ASSERT(identity_erased(&fixture.identity));
    } TEST_END
    fixture_close(&fixture);
    return failures;
}
#endif

int test_device_identity(void);
int test_device_identity(void)
{
#if defined(_WIN32)
    return identity_windows_creation_refused();
#else
    return identity_create_and_reopen() + identity_interrupted(1) +
        identity_interrupted(2) + identity_interrupted(3) + identity_foreign_directory() +
        identity_profile_refusals() + identity_missing_key() + identity_sweep_cases();
#endif
}
