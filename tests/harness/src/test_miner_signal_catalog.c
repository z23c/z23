/* purpose: Verify canonical ballot catalog vectors and rejection behavior. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/miner_signal_catalog.h"
#include "services/experimental_profile.h"
#include "experimental_profile_fixture.h"
#include "services/miner_signal_catalog_pin.h"
#include "json/json.h"
#include "test/test_core.h"
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif
#include "base/hex.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>

#define CAT_CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "miner_signal_catalog line %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static bool catalog_digest_changed(const struct miner_signal_catalog *catalog, const uint8_t original[32])
{
    struct miner_signal_schedule selected;
    return miner_signal_catalog_select(catalog, 0, &selected).ok &&
           memcmp(original, selected.catalog, 32) != 0;
}

#if !defined(_WIN32)
static bool pin_write(const char *path, const char *bytes, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(bytes, 1, n, f) == n;
    if (fclose(f)) ok = false;
    return ok;
}

/* Load the tracked release ballot through the real digest-bound loader. */
static int selected_release_catalog_cases(void)
{
    static const char expected[] =
        "bb447e1ae3827c976f4ff08a5b5ac7379fa486ce1bc13480f3e9db7e0dc733af";
    static const char mismatch[] =
        "ab447e1ae3827c976f4ff08a5b5ac7379fa486ce1bc13480f3e9db7e0dc733af";
    static const char genesis_hex[] =
        "e7788cffdd6cf6b0065d7a215345acb895173f319b1a5dd0b877b3420baaad0e";
    uint8_t genesis[32], expected_bytes[32];
    CAT_CHECK(zcl_hex_decode(genesis_hex, genesis, sizeof(genesis)));
    CAT_CHECK(zcl_hex_decode(expected, expected_bytes, sizeof(expected_bytes)));
    FILE *f = fopen("tests/fixtures/ironwood/selected-manifest.json", "rb");
    CAT_CHECK(f);
    char manifest[225];
    size_t n = fread(manifest, 1, sizeof(manifest), f);
    bool ok = !ferror(f) && n == 224 && feof(f);
    CAT_CHECK(fclose(f) == 0 && ok);
    char dir[512], ballots[600], path[720], wrong_path[720];
    CAT_CHECK(test_mkdtemp(dir, sizeof(dir), "selected_ballot_pin"));
    CAT_CHECK(snprintf(ballots, sizeof(ballots), "%s/ballots", dir) > 0);
    CAT_CHECK(mkdir(ballots, 0700) == 0);
    CAT_CHECK(snprintf(path, sizeof(path), "%s/%s.json", ballots, expected) > 0);
    CAT_CHECK(snprintf(wrong_path, sizeof(wrong_path), "%s/%s.json", ballots, mismatch) > 0);
    CAT_CHECK(pin_write(path, manifest, n) && pin_write(wrong_path, manifest, n));
    struct miner_signal_catalog_pin pin = {0};
    CAT_CHECK(miner_signal_catalog_pin_load(dir, expected, genesis, &pin).ok);
    struct miner_signal_schedule first = {0}, second = {0};
    CAT_CHECK(miner_signal_catalog_pin_select(&pin, 0, &first).ok);
    CAT_CHECK(miner_signal_catalog_pin_select(&pin, 1, &second).ok);
    CAT_CHECK(first.start == 121 && first.window == 20 && first.activation == 143 &&
              first.slot == 0 && first.slots == 2);
    CAT_CHECK(second.start == 121 && second.window == 20 && second.activation == 144 &&
              second.slot == 1 && second.slots == 2);
    CAT_CHECK(miner_signal_required_votes(first.window) == 19 &&
              miner_signal_required_votes(second.window) == 19);
    CAT_CHECK(!memcmp(first.catalog, expected_bytes, 32) &&
              !memcmp(second.catalog, expected_bytes, 32));
    struct miner_signal_catalog_pin before = pin;
    CAT_CHECK(!miner_signal_catalog_pin_load(dir, mismatch, genesis, &pin).ok);
    CAT_CHECK(!memcmp(&pin, &before, sizeof(pin)));
    CAT_CHECK(unlink(path) == 0 && unlink(wrong_path) == 0 && rmdir(ballots) == 0);
    test_cleanup_tmpdir(dir);
    return 0;
}

static int catalog_pin_cases(void)
{
    static const char manifest[] =
        "[\"1111111111111111111111111111111111111111111111111111111111111111\",100,20,"
        "[[\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",122],"
        "[\"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\",150]]]";
    static const char digest[] = "be8027db90c73984db54173ba98edd05ec137fad214ee500ae3b9e117b2894fe";
    uint8_t genesis[32]; memset(genesis, 0x22, sizeof(genesis));
    struct json_value doc = {0};
    CAT_CHECK(json_read(&doc, manifest, sizeof(manifest) - 1));
    struct miner_signal_catalog_pin pin = {0};
    CAT_CHECK(miner_signal_catalog_pin_parse(json_at(&doc, 0), json_at(&doc, 1),
        json_at(&doc, 2), json_at(&doc, 3), genesis, &pin).ok);
    json_free(&doc); /* pin owns every byte after the JSON is freed */
    struct miner_signal_schedule schedule = {0};
    CAT_CHECK(miner_signal_catalog_pin_select(&pin, 1, &schedule).ok);
    CAT_CHECK(schedule.slot == 1 && schedule.slots == 2 && schedule.activation == 150);
    char actual[65]; zcl_hex_encode(schedule.catalog, 32, actual);
    CAT_CHECK(!strcmp(actual, digest));
    struct miner_signal_catalog_pin before = pin;
    CAT_CHECK(!miner_signal_catalog_pin_select(&pin, 2, &schedule).ok);
    pin.entries[1].activation++;
    CAT_CHECK(!miner_signal_catalog_pin_select(&pin, 0, &schedule).ok);
    pin = before;

    char dir[512], ballots[600], path[720];
    CAT_CHECK(test_mkdtemp(dir, sizeof(dir), "ballot_pin"));
    CAT_CHECK(snprintf(ballots, sizeof(ballots), "%s/ballots", dir) > 0);
    CAT_CHECK(mkdir(ballots, 0700) == 0);
    CAT_CHECK(snprintf(path, sizeof(path), "%s/%s.json", ballots, digest) > 0);
    CAT_CHECK(!miner_signal_catalog_pin_load(dir, digest, genesis, &pin).ok);
    CAT_CHECK(pin_write(path, manifest, sizeof(manifest) - 1));
    memset(&pin, 0, sizeof(pin));
    CAT_CHECK(miner_signal_catalog_pin_load(dir, digest, genesis, &pin).ok);
    CAT_CHECK(!memcmp(&pin, &before, sizeof(pin)));
    uint8_t wrong[32]; memcpy(wrong, genesis, 32); wrong[0] ^= 1;
    CAT_CHECK(!miner_signal_catalog_pin_load(dir, digest, wrong, &pin).ok);
    CAT_CHECK(!memcmp(&pin, &before, sizeof(pin)));
    CAT_CHECK(!miner_signal_catalog_pin_load(dir, "BE8027DB90C73984DB54173BA98EDD05EC137FAD214EE500AE3B9E117B2894FE", genesis, &pin).ok);
    CAT_CHECK(pin_write(path, "[] trailing", sizeof("[] trailing") - 1));
    CAT_CHECK(!miner_signal_catalog_pin_load(dir, digest, genesis, &pin).ok);
    CAT_CHECK(pin_write(path, "[1,2,3,4]", sizeof("[1,2,3,4]") - 1));
    CAT_CHECK(!miner_signal_catalog_pin_load(dir, digest, genesis, &pin).ok);
    FILE *f = fopen(path, "wb"); CAT_CHECK(f);
    for (size_t i = 0; i < 32769; ++i) CAT_CHECK(fputc(' ', f) != EOF);
    CAT_CHECK(fclose(f) == 0);
    CAT_CHECK(!miner_signal_catalog_pin_load(dir, digest, genesis, &pin).ok);
    CAT_CHECK(!memcmp(&pin, &before, sizeof(pin)));
    CAT_CHECK(unlink(path) == 0 && rmdir(ballots) == 0);
    test_cleanup_tmpdir(dir);
    return 0;
}


#endif

static int profile_owned_cases(void)
{
    static const char pin_text[] =
        "d39f32009d8f47cadc323c2026dc515b46083619a4d8e675d5146c33b80d1604";
    uint8_t pin[32];
    CAT_CHECK(zcl_hex_decode(pin_text, pin, sizeof(pin)));
    uint8_t manifest[sizeof(profile_fixture_manifest)];
    uint8_t genesis[sizeof(profile_fixture_genesis)];
    memcpy(manifest, profile_fixture_manifest, sizeof(manifest));
    memcpy(genesis, profile_fixture_genesis, sizeof(genesis));
    struct experimental_profile value = {0};
    CAT_CHECK(experimental_profile_load(manifest, sizeof(manifest), genesis, sizeof(genesis),
                                        pin, &value) == EXPERIMENTAL_PROFILE_OK);
    CAT_CHECK(value.catalog.count == 1 && !memcmp(value.catalog.digest, pin, 32));
    uint8_t identity[32];
    CAT_CHECK(zcl_hex_decode("183dabcbb9c42160e69ad1e0518280a848fabd04bd8eab8637ee4a262365c133", identity, 32));
    CAT_CHECK(!memcmp(value.digest, identity, 32));
    CAT_CHECK(!memcmp(value.magic, "\xae\x49\x7c\x94", 4));
    char genesis_hex[65];
    uint256_get_hex(&value.genesis_hash, genesis_hex);
    CAT_CHECK(!strcmp(genesis_hex, "04b53334156424e5d5f630c5b282cac874e8ec73a8b0af99673c389bb18ae7ea"));
    struct experimental_profile copy = value;
    memset(&value, 0, sizeof(value));
    memset(manifest, 0, sizeof(manifest)); memset(genesis, 0, sizeof(genesis));
    CAT_CHECK(copy.genesis_size == sizeof(profile_fixture_genesis));
    CAT_CHECK(!memcmp(copy.genesis_wire, profile_fixture_genesis, sizeof(profile_fixture_genesis)));
    struct miner_signal_schedule schedule = {0};
    CAT_CHECK(miner_signal_catalog_pin_select(&copy.catalog, 0, &schedule).ok);
    CAT_CHECK(!memcmp(schedule.catalog, pin, 32));
    uint8_t before[sizeof(copy)];
    memcpy(before, &copy, sizeof(copy));
    pin[0] ^= 1;
    CAT_CHECK(experimental_profile_load(profile_fixture_manifest, sizeof(profile_fixture_manifest),
        profile_fixture_genesis, sizeof(profile_fixture_genesis), pin, &copy) ==
        EXPERIMENTAL_PROFILE_PIN_MISMATCH);
    CAT_CHECK(memcmp(&copy, before, sizeof(copy)) == 0);
    memcpy(genesis, profile_fixture_genesis, sizeof(genesis));
    genesis[100] ^= 1;
    CAT_CHECK(experimental_profile_load(profile_fixture_manifest, sizeof(profile_fixture_manifest),
        genesis, sizeof(genesis), pin, &copy) == EXPERIMENTAL_PROFILE_INVALID);
    CAT_CHECK(memcmp(&copy, before, sizeof(copy)) == 0);
    CAT_CHECK(experimental_profile_load(profile_fixture_manifest, sizeof(profile_fixture_manifest) - 1,
        profile_fixture_genesis, sizeof(profile_fixture_genesis), pin, &copy) ==
        EXPERIMENTAL_PROFILE_INVALID);
    CAT_CHECK(memcmp(&copy, before, sizeof(copy)) == 0);
    CAT_CHECK(experimental_profile_load(profile_fixture_manifest, sizeof(profile_fixture_manifest),
        profile_fixture_genesis, sizeof(profile_fixture_genesis), NULL, &copy) ==
        EXPERIMENTAL_PROFILE_INVALID);
    CAT_CHECK(memcmp(&copy, before, sizeof(copy)) == 0);
    /* Reuse an authenticated object for a different manifest. */
    memcpy(manifest, profile_fixture_manifest, sizeof(manifest));
    manifest[sizeof(manifest) - 36] ^= 1; /* Different revision. */
    manifest[56] ^= 1; /* Different genesis timestamp. */
    manifest[sizeof(manifest) - 4]++; /* Next activation height. */
    manifest[sizeof(manifest) - 1] = 0x80;
    CAT_CHECK(!experimental_profile_parse(manifest, sizeof(manifest), &copy).ok);
    CAT_CHECK(!memcmp(before, &copy, sizeof(copy)));
    manifest[sizeof(manifest) - 1] = 0;
    CAT_CHECK(experimental_profile_parse(manifest, sizeof(manifest), &copy).ok);
    CAT_CHECK(copy.catalog.entries[0].activation == 24);
    CAT_CHECK(memcmp(copy.digest, identity, sizeof(identity)) != 0);
    CAT_CHECK(copy.genesis_size == 0 && uint256_is_null(&copy.genesis_hash));
    static const uint8_t zeros[EXPERIMENTAL_GENESIS_SIZE] = {0};
    CAT_CHECK(!memcmp(copy.genesis_wire, zeros, sizeof(copy.genesis_wire)));
    CAT_CHECK(!memcmp(copy.catalog.digest, zeros, sizeof(copy.catalog.digest)));
    CAT_CHECK(!experimental_profile_select(&copy, 0, &schedule).ok);
    return 0;
}

int test_miner_signal_catalog(void)
{
    CAT_CHECK(profile_owned_cases() == 0);
    static const char *expected = "be8027db90c73984db54173ba98edd05ec137fad214ee500ae3b9e117b2894fe";
    struct miner_signal_catalog_entry entries[2] = {0};
    struct miner_signal_catalog c = { .start = 100, .window = 20, .count = 2, .entries = entries };
    memset(c.network_id, 0x11, 32);
    memset(c.genesis, 0x22, 32);
    for (unsigned i = 0; i < 32; ++i) {
        entries[0].rule_revision[i] = (uint8_t)i;
        entries[1].rule_revision[i] = (uint8_t)(i + 32);
    }
    entries[0].activation = 122; entries[1].activation = 150;
    uint8_t want[32];
    CAT_CHECK(zcl_hex_decode(expected, want, sizeof(want)));
    struct miner_signal_schedule a = {0}, b = {0};
    CAT_CHECK(miner_signal_catalog_select(&c, 0, &a).ok);
    CAT_CHECK(memcmp(a.catalog, want, 32) == 0);
    CAT_CHECK(a.start == 100 && a.window == 20 && a.activation == 122 && a.slot == 0 && a.slots == 2);
    CAT_CHECK(miner_signal_catalog_select(&c, 1, &b).ok);
    CAT_CHECK(memcmp(a.catalog, b.catalog, 32) == 0 && b.slot == 1 && b.activation == 150);
    c.network_id[0] ^= 1;
    CAT_CHECK(catalog_digest_changed(&c, a.catalog));
    c.network_id[0] ^= 1; c.genesis[0] ^= 1;
    CAT_CHECK(catalog_digest_changed(&c, a.catalog));
    c.genesis[0] ^= 1; entries[1].activation++;
    CAT_CHECK(catalog_digest_changed(&c, a.catalog));
    entries[1].activation--; entries[1].rule_revision[0]++;
    CAT_CHECK(catalog_digest_changed(&c, a.catalog));
    entries[1].rule_revision[0]--;
    c.window--;
    CAT_CHECK(catalog_digest_changed(&c, a.catalog));
    c.window++;
    c.start--;
    CAT_CHECK(catalog_digest_changed(&c, a.catalog));
    c.start++;
    c.count = 1;
    CAT_CHECK(catalog_digest_changed(&c, a.catalog));
    c.count = 2;
    struct miner_signal_schedule before = a;
    CAT_CHECK(!miner_signal_catalog_select(&c, 2, &a).ok && memcmp(&a, &before, sizeof(a)) == 0);
    CAT_CHECK(!miner_signal_catalog_select(&c, 0, NULL).ok);
    CAT_CHECK(!miner_signal_catalog_select(NULL, 0, &a).ok);
    c.count = 257; CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok); c.count = 0;
    CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok); c.count = 2;
    c.entries = NULL; CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok); c.entries = entries;
    memset(c.network_id, 0, 32); CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok);
    memset(c.network_id, 0x11, 32); memset(c.genesis, 0, 32);
    CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok); memset(c.genesis, 0x22, 32);
    entries[0].activation = 120; CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok);
    entries[0].activation = 121; CAT_CHECK(miner_signal_catalog_select(&c, 0, &b).ok);
    entries[0].activation = 122; c.start = INT32_MAX;
    CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok); c.start = 100;
    c.window = 0; CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok); c.window = 20;
    memcpy(entries[1].rule_revision, entries[0].rule_revision, 32);
    CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok);
    entries[1].rule_revision[0] = 0; entries[0].rule_revision[0] = 1;
    CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok);
    CAT_CHECK(memcmp(&a, &before, sizeof(a)) == 0);
    static struct miner_signal_catalog_entry all[256];
    for (unsigned i = 0; i < 256; ++i) {
        all[i].rule_revision[31] = (uint8_t)i;
        all[i].activation = 122;
    }
    c.entries = all; c.count = 256;
    CAT_CHECK(miner_signal_catalog_select(&c, 255, &b).ok);
    CAT_CHECK(b.slots == 256 && b.slot == 255 && b.activation == 122);
#if !defined(_WIN32)
    CAT_CHECK(catalog_pin_cases() == 0);
    CAT_CHECK(selected_release_catalog_cases() == 0);
#endif
    puts("miner_signal_catalog: vector, slot binding, mutations and rejection passed");
    return 0;
}
