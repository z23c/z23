/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_policy — the ZCODE local P2P ratio + anti-spam policy
 * (slice 11: contexts/commons/modules/vcs/package_policy.*, contexts/commons/modules/vcs/package_service.*, the
 * publish-frequency checkpoint in the zcode.package.publish.commit
 * handler, and the zcode seed status|ratio / zcode storage status
 * handlers in tools/command/native_zcode_seed_command.c).
 *
 * Coverage (adversarial first):
 *   1. Sybil upload loop: two keys uploading to each other — the ratio
 *      is LOCAL per key, there is no global ZCODE mint for bandwidth
 *      (the book never writes the reward ledger; bandwidth alone with
 *      zero earned score NEVER leaves the new-user tier), named.
 *   2. Repeated fake downloads: the same request id replayed earns no
 *      credit (duplicate-request-replay) and the offence is named;
 *      unverified / unsolicited / announcement / invalid-chunk /
 *      incomplete-staging bytes earn nothing, explicitly.
 *   3. The free allowance: a zero-score new user downloads public
 *      packages and publishes once per week; the allowance is a
 *      per-window rate limit, never a permanent denial.
 *   4. Publish frequency: the 2nd publish in one ISO week is rejected
 *      naming publish-frequency-limit — at the pure decision AND through
 *      the commit command (PUBLISH_FREQUENCY_LIMIT); the earned-
 *      contributor tier raises the allowance; the next ISO week resets.
 *   5. Pin allowance by tier against a REAL store's PINS pool usage.
 *   6. Offence accounting accumulates per kind and names kinds.
 *   7. Tier transitions at the exact thresholds (score gate first, then
 *      upload volume, then ratio >= 1).
 *   8. Determinism: replaying the durable wires reproduces the book
 *      exactly; corrupt / id-mismatched wires are skipped and counted.
 *
 * Handlers run in-process on ./test-tmp datadirs; CHAIN_MAIN is pinned so
 * the chain-id and reward rules are deterministic. */

#include "test/test_core.h"

#include "command/native_command.h"

#include "chain/chainparams.h"
#include "core/uint256.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "vcs/package_accept.h"
#include "vcs/package_manifest.h"
#include "vcs/package_policy.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"
#include "vcs/package_reward.h"
#include "vcs/service_receipt.h"

#include <secp256k1.h>
#include "vcs/package_service.h"
#include "vcs/package_store.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZPY_CHECK(name, expr) do {                                     \
    if (expr) { printf("  zcode_policy: %s... OK\n", (name)); }        \
    else { printf("  zcode_policy: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* ── small fixtures (the test_zcode_rank / test_zcode_publish pattern) ── */

static void zpy_hex_enc(const uint8_t *in, size_t len, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[in[i] & 0xf];
    }
    out[2 * len] = '\0';
}

static bool zpy_mkdir_p(const char *path)
{
    char buf[4400];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf))
        return false;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

static bool zpy_rm_rf(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0;
    DIR *dir = opendir(path);
    if (!dir)
        return false;
    bool ok = true;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[4400];
        int n = snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child)) {
            ok = false;
            continue;
        }
        if (!zpy_rm_rf(child))
            ok = false;
    }
    closedir(dir);
    if (rmdir(path) != 0)
        ok = false;
    return ok;
}

static void zpy_root(uint8_t seed, uint8_t out[32])
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(seed + i);
    if (out[0] == 0)
        out[0] = 1;
}

static void zpy_pub(uint8_t seed, uint8_t out[33])
{
    out[0] = 0x02;
    for (size_t i = 1; i < 33; i++)
        out[i] = (uint8_t)(seed + i);
}

/* ── 1. the local ratio (pure) ──────────────────────────────────────── */

static int t_ratio(void)
{
    int failures = 0;
    ZPY_CHECK("ratio: zero downloads divides by 1",
              vcs_policy_ratio_milli(0, 0) == 0 &&
              vcs_policy_ratio_milli(500, 0) == 500000);
    ZPY_CHECK("ratio: exact milli",
              vcs_policy_ratio_milli(1000, 1000) == 1000 &&
              vcs_policy_ratio_milli(1500, 1000) == 1500 &&
              vcs_policy_ratio_milli(1, 3) == 333 &&
              vcs_policy_ratio_milli(1, 1000000) == 0);
    ZPY_CHECK("ratio: saturates instead of wrapping",
              vcs_policy_ratio_milli(UINT64_MAX, 1) == UINT64_MAX &&
              vcs_policy_ratio_milli(UINT64_MAX / 1000 + 1, 1) ==
                  UINT64_MAX);
    ZPY_CHECK("ratio: only verified bytes move it",
              vcs_policy_ratio_milli(2048, 1024) == 2000);
    return failures;
}

/* ── 2. tier resolution + the no-global-mint property ───────────────── */

static int t_tiers(void)
{
    int failures = 0;
    ZPY_CHECK("tiers: zero facts is a new user",
              vcs_policy_tier_for(0, 0, 0) == VCS_POLICY_TIER_NEW_USER);
    ZPY_CHECK("tiers: one point below the contributor threshold",
              vcs_policy_tier_for(VCS_POLICY_TIER_CONTRIBUTOR_MIN_SCORE - 1,
                                  UINT64_C(1) << 40, 0) ==
                  VCS_POLICY_TIER_NEW_USER);
    ZPY_CHECK("tiers: the threshold makes a contributor",
              vcs_policy_tier_for(VCS_POLICY_TIER_CONTRIBUTOR_MIN_SCORE,
                                  0, 0) == VCS_POLICY_TIER_EARNED_CONTRIBUTOR);

    /* THE SYBIL PROPERTY: bandwidth alone buys nothing. Any amount of
     * verified upload with zero earned score is still a new user — two
     * Sybil nodes uploading to each other never mint service priority. */
    ZPY_CHECK("tiers: huge upload + zero score stays new-user (no "
              "global mint for bandwidth)",
              vcs_policy_tier_for(0, UINT64_C(1) << 40, 0) ==
                  VCS_POLICY_TIER_NEW_USER &&
              vcs_policy_tier_for(VCS_POLICY_TIER_CONTRIBUTOR_MIN_SCORE - 1,
                                  UINT64_MAX / 2, 1) ==
                  VCS_POLICY_TIER_NEW_USER);

    /* Seeder needs ALL THREE: the score, the upload volume, ratio >= 1. */
    ZPY_CHECK("tiers: seeder needs the score",
              vcs_policy_tier_for(VCS_POLICY_TIER_SEEDER_MIN_SCORE - 1,
                                  VCS_POLICY_TIER_SEEDER_MIN_UPLOAD_BYTES,
                                  1) == VCS_POLICY_TIER_EARNED_CONTRIBUTOR);
    ZPY_CHECK("tiers: seeder needs the upload volume",
              vcs_policy_tier_for(VCS_POLICY_TIER_SEEDER_MIN_SCORE,
                                  VCS_POLICY_TIER_SEEDER_MIN_UPLOAD_BYTES - 1,
                                  0) == VCS_POLICY_TIER_EARNED_CONTRIBUTOR);
    ZPY_CHECK("tiers: seeder needs ratio >= 1",
              vcs_policy_tier_for(VCS_POLICY_TIER_SEEDER_MIN_SCORE,
                                  VCS_POLICY_TIER_SEEDER_MIN_UPLOAD_BYTES,
                                  VCS_POLICY_TIER_SEEDER_MIN_UPLOAD_BYTES * 2)
                  == VCS_POLICY_TIER_EARNED_CONTRIBUTOR);
    ZPY_CHECK("tiers: the full threshold set makes a seeder",
              vcs_policy_tier_for(VCS_POLICY_TIER_SEEDER_MIN_SCORE,
                                  VCS_POLICY_TIER_SEEDER_MIN_UPLOAD_BYTES,
                                  VCS_POLICY_TIER_SEEDER_MIN_UPLOAD_BYTES)
                  == VCS_POLICY_TIER_VERIFIED_SEEDER);
    ZPY_CHECK("tiers: strings",
              strcmp(vcs_policy_tier_string(VCS_POLICY_TIER_NEW_USER),
                     "new-user") == 0 &&
              strcmp(vcs_policy_tier_string(
                         VCS_POLICY_TIER_EARNED_CONTRIBUTOR),
                     "earned-contributor") == 0 &&
              strcmp(vcs_policy_tier_string(VCS_POLICY_TIER_VERIFIED_SEEDER),
                     "verified-seeder") == 0 &&
              strcmp(vcs_policy_tier_string(VCS_POLICY_TIER_COUNT),
                     "unknown") == 0);
    return failures;
}

/* ── 3. the pure decisions + window arithmetic ──────────────────────── */

static int t_decisions(void)
{
    int failures = 0;

    /* ISO week arithmetic: day 20000 is 2024-10-04, a Friday; its week
     * starts Monday 19996. Day 20007 starts the NEXT week (20003). */
    ZPY_CHECK("week: Friday's week starts the prior Monday",
              vcs_policy_week_start(20000) == 19996 &&
              vcs_policy_week_start(19996) == 19996 &&
              vcs_policy_week_start(20002) == 19996 &&
              vcs_policy_week_start(20003) == 20003 &&
              vcs_policy_week_start(0) == -3); /* 1970-01-01 Thursday */

    /* Publish frequency: the free allowance is 1/week for a new user. */
    struct vcs_policy_decision d = vcs_policy_check_publish(
        VCS_POLICY_TIER_NEW_USER, 0);
    ZPY_CHECK("publish: a new user's first publish is allowed",
              d.allow && d.rule == NULL);
    d = vcs_policy_check_publish(VCS_POLICY_TIER_NEW_USER, 1);
    ZPY_CHECK("publish: the 2nd in a week names publish-frequency-limit",
              !d.allow &&
              strcmp(d.rule, VCS_POLICY_RULE_PUBLISH_FREQUENCY) == 0 &&
              strcmp(d.rule, "publish-frequency-limit") == 0);
    ZPY_CHECK("publish: contributor 4/week, seeder 16/week",
              vcs_policy_check_publish(VCS_POLICY_TIER_EARNED_CONTRIBUTOR,
                                       3).allow &&
              !vcs_policy_check_publish(VCS_POLICY_TIER_EARNED_CONTRIBUTOR,
                                        4).allow &&
              vcs_policy_check_publish(VCS_POLICY_TIER_VERIFIED_SEEDER,
                                       15).allow &&
              !vcs_policy_check_publish(VCS_POLICY_TIER_VERIFIED_SEEDER,
                                        16).allow);

    /* Download allowance: the FREE allowance always exists for a
     * zero-score user; exhausting it is a per-window rate limit. */
    d = vcs_policy_check_download(VCS_POLICY_TIER_NEW_USER, 0, 1024);
    ZPY_CHECK("download: the free allowance admits a zero-score user",
              d.allow);
    d = vcs_policy_check_download(VCS_POLICY_TIER_NEW_USER, 0,
                                  VCS_POLICY_FREE_WEEKLY_DOWNLOAD_BYTES);
    ZPY_CHECK("download: the whole free allowance is admissible",
              d.allow);
    d = vcs_policy_check_download(VCS_POLICY_TIER_NEW_USER, 0,
                                  VCS_POLICY_FREE_WEEKLY_DOWNLOAD_BYTES + 1);
    ZPY_CHECK("download: past the free allowance names the rule",
              !d.allow &&
              strcmp(d.rule, "download-allowance-exhausted") == 0);
    d = vcs_policy_check_download(VCS_POLICY_TIER_NEW_USER,
                                  VCS_POLICY_FREE_WEEKLY_DOWNLOAD_BYTES - 1,
                                  2);
    ZPY_CHECK("download: the boundary is exact",
              !d.allow &&
              vcs_policy_check_download(VCS_POLICY_TIER_NEW_USER,
                                        VCS_POLICY_FREE_WEEKLY_DOWNLOAD_BYTES - 1,
                                        1).allow);

    /* Concurrent downloads / queue priority. */
    ZPY_CHECK("concurrent: per-tier limits",
              vcs_policy_check_concurrent_downloads(VCS_POLICY_TIER_NEW_USER,
                                                    0).allow &&
              !vcs_policy_check_concurrent_downloads(
                  VCS_POLICY_TIER_NEW_USER, 1).allow &&
              vcs_policy_check_concurrent_downloads(
                  VCS_POLICY_TIER_EARNED_CONTRIBUTOR, 3).allow &&
              !vcs_policy_check_concurrent_downloads(
                  VCS_POLICY_TIER_EARNED_CONTRIBUTOR, 4).allow &&
              !vcs_policy_check_concurrent_downloads(
                  VCS_POLICY_TIER_VERIFIED_SEEDER, 8).allow);
    ZPY_CHECK("priority: strictly ordered by tier",
              vcs_policy_queue_priority(VCS_POLICY_TIER_NEW_USER) <
                  vcs_policy_queue_priority(
                      VCS_POLICY_TIER_EARNED_CONTRIBUTOR) &&
              vcs_policy_queue_priority(VCS_POLICY_TIER_EARNED_CONTRIBUTOR) <
                  vcs_policy_queue_priority(VCS_POLICY_TIER_VERIFIED_SEEDER));

    /* Pin allowance: new users have none — pins are earned. */
    d = vcs_policy_check_pin(VCS_POLICY_TIER_NEW_USER, 0, 1);
    ZPY_CHECK("pin: a new user has no pin allowance",
              !d.allow &&
              strcmp(d.rule, "pin-allowance-exceeded") == 0);
    ZPY_CHECK("pin: contributor allowance is exact",
              vcs_policy_check_pin(VCS_POLICY_TIER_EARNED_CONTRIBUTOR, 0,
                                   UINT64_C(256) * 1024u * 1024u).allow &&
              !vcs_policy_check_pin(VCS_POLICY_TIER_EARNED_CONTRIBUTOR, 0,
                                    UINT64_C(256) * 1024u * 1024u + 1).allow &&
              !vcs_policy_check_pin(VCS_POLICY_TIER_EARNED_CONTRIBUTOR,
                                    UINT64_C(256) * 1024u * 1024u, 1).allow &&
              vcs_policy_check_pin(VCS_POLICY_TIER_VERIFIED_SEEDER, 0,
                                   UINT64_C(1) << 30).allow);

    /* Announce rate / request burst. */
    ZPY_CHECK("announce: the new-user serving-set inventory bound is exact",
              vcs_policy_check_announce(VCS_POLICY_TIER_NEW_USER, 0).allow &&
              vcs_policy_check_announce(VCS_POLICY_TIER_NEW_USER,
                                        VCS_POLICY_FREE_ANNOUNCE_PER_HOUR - 1)
                  .allow &&
              !vcs_policy_check_announce(VCS_POLICY_TIER_NEW_USER,
                                         VCS_POLICY_FREE_ANNOUNCE_PER_HOUR)
                   .allow &&
              strcmp(vcs_policy_check_announce(
                         VCS_POLICY_TIER_NEW_USER,
                         VCS_POLICY_FREE_ANNOUNCE_PER_HOUR)
                         .rule,
                     "announce-rate-limit") == 0 &&
              vcs_policy_check_announce(
                  VCS_POLICY_TIER_EARNED_CONTRIBUTOR,
                  VCS_POLICY_FREE_ANNOUNCE_PER_HOUR - 1)
                  .allow &&
              !vcs_policy_check_announce(
                  VCS_POLICY_TIER_EARNED_CONTRIBUTOR,
                  VCS_POLICY_FREE_ANNOUNCE_PER_HOUR)
                   .allow);
    ZPY_CHECK("burst: the request burst allowance is exact",
              vcs_policy_check_request_burst(VCS_POLICY_TIER_NEW_USER,
                                             VCS_POLICY_FREE_REQUEST_BURST_PER_WINDOW - 1u).allow &&
              !vcs_policy_check_request_burst(VCS_POLICY_TIER_NEW_USER,
                                              VCS_POLICY_FREE_REQUEST_BURST_PER_WINDOW).allow &&
              strcmp(vcs_policy_check_request_burst(
                         VCS_POLICY_TIER_NEW_USER,
                         VCS_POLICY_FREE_REQUEST_BURST_PER_WINDOW).rule,
                     "request-burst-limit") == 0);

    /* Verifier eligibility: self-verification first, then the score
     * floor, then the approved-key allowlist — each a named rule. */
    d = vcs_policy_check_verifier(UINT64_MAX, true, true);
    ZPY_CHECK("verifier: self-verification is named first",
              !d.allow && strcmp(d.rule, "self-verification") == 0);
    d = vcs_policy_check_verifier(VCS_POLICY_VERIFIER_MIN_SCORE - 1, true,
                                  false);
    ZPY_CHECK("verifier: below the score floor",
              !d.allow && strcmp(d.rule, "verifier-score-too-low") == 0);
    d = vcs_policy_check_verifier(VCS_POLICY_VERIFIER_MIN_SCORE, false,
                                  false);
    ZPY_CHECK("verifier: not an approved key",
              !d.allow && strcmp(d.rule, "verifier-not-approved") == 0);
    ZPY_CHECK("verifier: the full set passes",
              vcs_policy_check_verifier(VCS_POLICY_VERIFIER_MIN_SCORE, true,
                                        false).allow);

    /* The frozen never-credit + offence name lists. */
    ZPY_CHECK("no-credit: the six frozen names",
              strcmp(vcs_policy_no_credit_string(
                         VCS_POLICY_NO_CREDIT_ANNOUNCEMENT),
                     "announcement-bytes") == 0 &&
              strcmp(vcs_policy_no_credit_string(
                         VCS_POLICY_NO_CREDIT_UNVERIFIED),
                     "unverified-bytes") == 0 &&
              strcmp(vcs_policy_no_credit_string(
                         VCS_POLICY_NO_CREDIT_DUPLICATE_REQUEST),
                     "duplicate-request-replay") == 0 &&
              strcmp(vcs_policy_no_credit_string(
                         VCS_POLICY_NO_CREDIT_UNREQUESTED),
                     "unrequested-bytes") == 0 &&
              strcmp(vcs_policy_no_credit_string(
                         VCS_POLICY_NO_CREDIT_INVALID_CHUNK),
                     "invalid-chunk") == 0 &&
              strcmp(vcs_policy_no_credit_string(
                         VCS_POLICY_NO_CREDIT_INCOMPLETE_STAGING),
                     "incomplete-staging") == 0 &&
              VCS_POLICY_NO_CREDIT_COUNT == 6);
    ZPY_CHECK("offences: the five frozen names",
              strcmp(vcs_policy_offence_string(
                         VCS_POLICY_OFFENCE_DUPLICATE_REQUEST),
                     "duplicate-request") == 0 &&
              strcmp(vcs_policy_offence_string(
                         VCS_POLICY_OFFENCE_UNREQUESTED_BYTES),
                     "unrequested-bytes") == 0 &&
              strcmp(vcs_policy_offence_string(
                         VCS_POLICY_OFFENCE_INVALID_CHUNK),
                     "invalid-chunk") == 0 &&
              strcmp(vcs_policy_offence_string(
                         VCS_POLICY_OFFENCE_ANNOUNCE_FLOOD),
                     "announce-flood") == 0 &&
              strcmp(vcs_policy_offence_string(
                         VCS_POLICY_OFFENCE_REQUEST_FLOOD),
                     "request-flood") == 0 &&
              VCS_POLICY_OFFENCE_COUNT == 5);
    return failures;
}

/* ── 4. the service book (adversarial: Sybil loops, replays, no-credit) ── */

/* Serialize a key's totals + the book-wide totals (for rebuild equality). */
static void zpy_book_dump(const struct vcs_service_book *book,
                          const uint8_t key[33], int64_t day, char *out,
                          size_t out_size)
{
    struct vcs_service_key_totals kt;
    (void)vcs_service_key_totals(book, key, day, &kt);
    struct vcs_service_book_totals bt;
    vcs_service_book_totals(book, &bt);
    size_t off = 0;
    off += (size_t)snprintf(
        out + off, out_size - off,
        "present=%d;up=%llu;down=%llu;dtw=%llu;ratio=%llu;pubs=%u;ptw=%u;"
        "offtot=%u;ncbytes=%llu;keys=%zu;events=%zu;bup=%llu;bdown=%llu;",
        (int)kt.present, (unsigned long long)kt.verified_bytes_uploaded,
        (unsigned long long)kt.verified_bytes_downloaded,
        (unsigned long long)kt.downloaded_this_week,
        (unsigned long long)kt.ratio_milli, kt.publish_events,
        kt.publishes_this_week, kt.offence_total,
        (unsigned long long)kt.no_credit_bytes,
        vcs_service_book_key_count(book),
        vcs_service_book_event_count(book),
        (unsigned long long)bt.verified_bytes_uploaded,
        (unsigned long long)bt.verified_bytes_downloaded);
    for (size_t i = 0; i < VCS_POLICY_OFFENCE_COUNT; i++)
        off += (size_t)snprintf(out + off, out_size - off, "o%zu=%u;", i,
                                kt.offences[i]);
    for (size_t i = 0; i < VCS_POLICY_NO_CREDIT_COUNT; i++)
        off += (size_t)snprintf(out + off, out_size - off, "n%zu=%llu;", i,
                                (unsigned long long)kt.no_credit_events[i]);
}

static int t_book(void)
{
    int failures = 0;
    char zcode_dir[4400];
    snprintf(zcode_dir, sizeof(zcode_dir), "test-tmp/zpy_book_%ld/zcode",
             (long)getpid());
    zpy_rm_rf(zcode_dir);
    ZPY_CHECK("book: datadir created", zpy_mkdir_p(zcode_dir));

    uint8_t key_a[33], key_b[33], req1[32], req2[32], req3[32], rel1[32],
        rel2[32];
    zpy_pub(0x51, key_a);
    zpy_pub(0x52, key_b);
    zpy_root(0x61, req1);
    zpy_root(0x62, req2);
    zpy_root(0x63, req3);
    zpy_root(0x71, rel1);
    zpy_root(0x72, rel2);

    struct vcs_service_book *book = vcs_service_book_load(zcode_dir);
    ZPY_CHECK("book: an empty book loads", book != NULL);
    if (!book)
        return failures + 1;

    /* Verified upload credits once; the exact redelivery is a dedup
     * DUPLICATE; a REPLAYED request id (different bytes or day) earns
     * nothing and names duplicate-request-replay. */
    ZPY_CHECK("book: verified upload credits",
              vcs_service_credit_upload(book, key_a, req1, 1048576,
                                        20000) == VCS_SERVICE_CREDIT_OK);
    ZPY_CHECK("book: exact redelivery is an idempotent duplicate",
              vcs_service_credit_upload(book, key_a, req1, 1048576,
                                        20000) == VCS_SERVICE_CREDIT_DUPLICATE);
    ZPY_CHECK("book: replayed request id earns nothing (named)",
              vcs_service_credit_upload(book, key_a, req1, 2097152,
                                        20001) ==
                  VCS_SERVICE_CREDIT_REPLAYED_REQUEST &&
              strcmp(vcs_service_credit_result_string(
                         VCS_SERVICE_CREDIT_REPLAYED_REQUEST),
                     "duplicate-request-replay") == 0);
    struct vcs_service_key_totals kt;
    ZPY_CHECK("book: totals readable",
              vcs_service_key_totals(book, key_a, 20000, &kt));
    ZPY_CHECK("book: only the first delivery counted",
              kt.present && kt.verified_bytes_uploaded == 1048576 &&
              kt.verified_bytes_downloaded == 0 &&
              kt.ratio_milli == 1048576000);

    /* The replay is then a NAMED offence that accumulates per kind. */
    ZPY_CHECK("book: the duplicate-request offence records",
              vcs_service_record_offence(book, key_a,
                                         VCS_POLICY_OFFENCE_DUPLICATE_REQUEST,
                                         20001) == VCS_SERVICE_RECORD_OK);
    ZPY_CHECK("book: offence kinds accumulate separately",
              vcs_service_record_offence(book, key_a,
                                         VCS_POLICY_OFFENCE_INVALID_CHUNK,
                                         20001) == VCS_SERVICE_RECORD_OK &&
              vcs_service_record_offence(book, key_a,
                                         VCS_POLICY_OFFENCE_INVALID_CHUNK,
                                         20001) == VCS_SERVICE_RECORD_OK);
    ZPY_CHECK("book: offence totals name kinds",
              vcs_service_key_totals(book, key_a, 20000, &kt) &&
              kt.offences[VCS_POLICY_OFFENCE_DUPLICATE_REQUEST] == 1 &&
              kt.offences[VCS_POLICY_OFFENCE_INVALID_CHUNK] == 2 &&
              kt.offences[VCS_POLICY_OFFENCE_UNREQUESTED_BYTES] == 0 &&
              kt.offence_total == 3);

    /* What NEVER earns credit: announcements, unverified bytes,
     * unrequested bytes, invalid chunks, incomplete staging — recorded
     * as no-credit facts; neither side of the ratio moves. */
    ZPY_CHECK("book: no-credit facts record",
              vcs_service_record_no_credit(
                  book, key_a, VCS_POLICY_NO_CREDIT_ANNOUNCEMENT, 512,
                  20001) == VCS_SERVICE_RECORD_OK &&
              vcs_service_record_no_credit(
                  book, key_a, VCS_POLICY_NO_CREDIT_UNVERIFIED, 65536,
                  20001) == VCS_SERVICE_RECORD_OK &&
              vcs_service_record_no_credit(
                  book, key_a, VCS_POLICY_NO_CREDIT_UNREQUESTED, 999,
                  20001) == VCS_SERVICE_RECORD_OK &&
              vcs_service_record_no_credit(
                  book, key_a, VCS_POLICY_NO_CREDIT_INVALID_CHUNK, 4096,
                  20001) == VCS_SERVICE_RECORD_OK &&
              vcs_service_record_no_credit(
                  book, key_a, VCS_POLICY_NO_CREDIT_INCOMPLETE_STAGING,
                  12345, 20001) == VCS_SERVICE_RECORD_OK);
    ZPY_CHECK("book: no-credit never moves the ratio",
              vcs_service_key_totals(book, key_a, 20000, &kt) &&
              kt.verified_bytes_uploaded == 1048576 &&
              kt.verified_bytes_downloaded == 0 &&
              kt.no_credit_events[VCS_POLICY_NO_CREDIT_ANNOUNCEMENT] == 1 &&
              kt.no_credit_events[VCS_POLICY_NO_CREDIT_UNVERIFIED] == 1 &&
              kt.no_credit_events[VCS_POLICY_NO_CREDIT_UNREQUESTED] == 1 &&
              kt.no_credit_events[VCS_POLICY_NO_CREDIT_INVALID_CHUNK] == 1 &&
              kt.no_credit_events[VCS_POLICY_NO_CREDIT_INCOMPLETE_STAGING] ==
                  1 &&
              kt.no_credit_bytes == 512 + 65536 + 999 + 4096 + 12345);

    /* Bad inputs are rejected without logging-or-crashing. */
    ZPY_CHECK("book: bad inputs rejected",
              vcs_service_credit_upload(book, key_a, req2, 0, 20000) ==
                  VCS_SERVICE_CREDIT_BAD_INPUT &&
              vcs_service_record_offence(book, key_a,
                                         VCS_POLICY_OFFENCE_COUNT, 20000) ==
                  VCS_SERVICE_RECORD_BAD_INPUT);

    /* SYBIL UPLOAD LOOP: key B "uploads to" key A and vice versa. On
     * this node's book each key's facts are LOCAL: both can hold
     * verified-upload credit (this node verifiably served them), but
     * (a) the book wrote NOTHING to the reward ledger (no global mint),
     * and (b) with zero earned score both stay new-user tier. */
    ZPY_CHECK("book: the Sybil pair's mutual uploads are local facts",
              vcs_service_credit_upload(book, key_b, req2, 1048576,
                                        20000) == VCS_SERVICE_CREDIT_OK &&
              vcs_service_credit_download(book, key_b, req3, 1048576,
                                          20000) == VCS_SERVICE_CREDIT_OK);
    struct vcs_service_book_totals bt;
    vcs_service_book_totals(book, &bt);
    ZPY_CHECK("book: book-wide totals are plain service facts",
              bt.verified_bytes_uploaded == 2 * 1048576 &&
              bt.verified_bytes_downloaded == 1048576);
    {
        struct vcs_reward_ledger *ledger =
            vcs_reward_ledger_load(zcode_dir);
        ZPY_CHECK("book: NO global mint — the reward ledger is untouched",
                  ledger != NULL &&
                  vcs_reward_ledger_entry_count(ledger) == 0 &&
                  vcs_reward_ledger_fact_count(ledger) == 0);
        vcs_reward_ledger_free(ledger);
    }
    struct vcs_service_key_totals kb;
    ZPY_CHECK("book: Sybil key with zero score stays new-user",
              vcs_service_key_totals(book, key_b, 20000, &kb) &&
              vcs_policy_tier_for(0, kb.verified_bytes_uploaded,
                                  kb.verified_bytes_downloaded) ==
                  VCS_POLICY_TIER_NEW_USER);

    /* Publish events: dedup by release id (republishing the same package
     * earns no second event); the ISO-week count is exact. */
    ZPY_CHECK("book: publish records",
              vcs_service_record_publish(book, key_a, rel1, 20000) ==
                  VCS_SERVICE_RECORD_OK);
    ZPY_CHECK("book: republishing the same package is a dedup duplicate",
              vcs_service_record_publish(book, key_a, rel1, 20001) ==
                  VCS_SERVICE_RECORD_DUPLICATE);
    ZPY_CHECK("book: a distinct release in the same week counts",
              vcs_service_record_publish(book, key_a, rel2, 20001) ==
                  VCS_SERVICE_RECORD_OK &&
              vcs_service_key_totals(book, key_a, 20000, &kt) &&
              kt.publish_events == 2 && kt.publishes_this_week == 2 &&
              vcs_service_key_totals(book, key_a, 20003, &kt) &&
              kt.publishes_this_week == 0); /* the next ISO week */

    /* Weekly download windows: downloads in week W and W+1 land in
     * separate buckets. */
    ZPY_CHECK("book: downloads credit per request id",
              vcs_service_credit_download(book, key_a, req2, 1000,
                                          20000) == VCS_SERVICE_CREDIT_OK &&
              vcs_service_credit_download(book, key_a, req3, 2000,
                                          20007) == VCS_SERVICE_CREDIT_OK);
    ZPY_CHECK("book: the weekly download window is exact",
              vcs_service_key_totals(book, key_a, 20000, &kt) &&
              kt.downloaded_this_week == 1000 &&
              vcs_service_key_totals(book, key_a, 20007, &kt) &&
              kt.downloaded_this_week == 2000 &&
              kt.verified_bytes_downloaded == 3000);

    /* Determinism: a reload from the durable wires reproduces the book
     * EXACTLY, and redelivery after the reload is still a dedup no-op. */
    char dump_before[1024];
    zpy_book_dump(book, key_a, 20000, dump_before, sizeof(dump_before));
    size_t events_before = vcs_service_book_event_count(book);
    vcs_service_book_free(book);
    book = vcs_service_book_load(zcode_dir);
    ZPY_CHECK("book: reload succeeds", book != NULL);
    char dump_after[1024];
    zpy_book_dump(book, key_a, 20000, dump_after, sizeof(dump_after));
    ZPY_CHECK("book: the replayed book is byte-identical",
              strcmp(dump_before, dump_after) == 0 &&
              vcs_service_book_event_count(book) == events_before);
    ZPY_CHECK("book: redelivery after reload is an idempotent duplicate",
              vcs_service_credit_upload(book, key_a, req1, 1048576,
                                        20000) == VCS_SERVICE_CREDIT_DUPLICATE);
    ZPY_CHECK("book: request replay after reload earns nothing",
              vcs_service_credit_upload(book, key_a, req1, 1048576,
                                        20002) ==
                  VCS_SERVICE_CREDIT_REPLAYED_REQUEST);
    ZPY_CHECK("book: publish redelivery after reload is deduped",
              vcs_service_record_publish(book, key_a, rel1, 20002) ==
                  VCS_SERVICE_RECORD_DUPLICATE);

    /* Corrupt wires are skipped and counted: garbage bytes under a hex
     * name, and a valid wire under the WRONG (id-mismatched) name. */
    vcs_service_book_free(book);
    {
        char evdir[4400];
        snprintf(evdir, sizeof(evdir), "%s/service/events", zcode_dir);
        ZPY_CHECK("book: events dir exists",
                  zpy_mkdir_p(evdir));
        /* The two literal junk names below are exactly 64 characters — the
         * same length as a real event's SHA3-256 hex id — but never a real
         * id themselves (a real hash landing on 64 repeated 'a's or 'b's is
         * a 1-in-16^64 event). Keep them as named constants so the
         * "which file is real" logic below can compare by EXACT name
         * instead of a "starts with 'a'/'b'" heuristic — a real hash id is
         * built from 16 possible hex digits per position, so roughly 1 in
         * 8 real ids legitimately starts with 'a' or 'b', and treating
         * those as junk was a second, compounding bug (see below). */
        static const char junk_name_a[] =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        static const char junk_name_b[] =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        char junk_path[4400];
        snprintf(junk_path, sizeof(junk_path), "%s/%s", evdir, junk_name_a);
        uint8_t junk[VCS_SERVICE_WIRE_BYTES];
        memset(junk, 0x5a, sizeof(junk));
        FILE *jf = fopen(junk_path, "wb");
        ZPY_CHECK("book: junk wire planted",
                  jf && fwrite(junk, 1, sizeof(junk), jf) == sizeof(junk) &&
                  fclose(jf) == 0);
        /* A valid-grammar wire whose content id != its filename. */
        struct vcs_service_book *tmp = vcs_service_book_load(zcode_dir);
        ZPY_CHECK("book: junk wire counted corrupt on the way",
                  tmp != NULL && vcs_service_book_corrupt_count(tmp) == 1);
        vcs_service_book_free(tmp);
        snprintf(junk_path, sizeof(junk_path), "%s/%s", evdir, junk_name_b);
        uint8_t other_key[33], other_req[32];
        zpy_pub(0x77, other_key);
        zpy_root(0x78, other_req);

        /* Snapshot every real event filename already on disk BEFORE
         * planting the new one below. readdir() enumeration order is NOT
         * creation order — ext4's htree directory index hashes names with
         * a per-filesystem random seed set at mkfs time, so "the last
         * 64-char match seen while iterating" is whichever pre-existing
         * event that filesystem's hash happens to enumerate last, not
         * necessarily the file this block is about to write. By this
         * point in t_book() there are already ~15 other real event files
         * on disk (key_a's upload, offences, no-credit facts, the Sybil
         * pair's events, publishes, downloads), so that host-dependent
         * pick was never guaranteed to be the intended one — it could
         * rename away a DIFFERENT, already-counted real event instead,
         * silently dropping it from the book's totals depending on the
         * filesystem's hash seed. Find the newly planted file by set
         * difference instead, which is correct regardless of enumeration
         * order.
         *
         * Only the two EXACT junk_name_a/junk_name_b strings are excluded
         * — not "any name starting with 'a' or 'b'". A real event id is a
         * SHA3-256 hex digest: any of its 16 hex digits is equally likely
         * in the first position, so roughly 1 in 8 genuine ids legitimately
         * start with 'a' or 'b'. An earlier revision of this fix filtered
         * by first character and silently misclassified those genuine ids
         * as junk, which broke the very set-difference it was trying to
         * make reliable. */
        enum { ZPY_MAX_EVENT_NAMES = 4096 };
        static char before_names[ZPY_MAX_EVENT_NAMES][65];
        size_t before_count = 0;
        {
            DIR *ed0 = opendir(evdir);
            struct dirent *ent0;
            while (ed0 && (ent0 = readdir(ed0)) != NULL &&
                   before_count < ZPY_MAX_EVENT_NAMES) {
                if (strlen(ent0->d_name) == 64 &&
                    strcmp(ent0->d_name, junk_name_a) != 0 &&
                    strcmp(ent0->d_name, junk_name_b) != 0) {
                    snprintf(before_names[before_count], 65, "%s",
                             ent0->d_name);
                    before_count++;
                }
            }
            if (ed0)
                closedir(ed0);
        }

        struct vcs_service_book *plant = vcs_service_book_load(zcode_dir);
        /* Record a real event, then RENAME its file to a wrong name. */
        ZPY_CHECK("book: plant event",
                  vcs_service_credit_upload(plant, other_key, other_req,
                                            42, 20000) ==
                      VCS_SERVICE_CREDIT_OK);
        vcs_service_book_free(plant);
        char real_path[4400] = "";
        {
            DIR *ed = opendir(evdir);
            struct dirent *ent;
            while (ed && (ent = readdir(ed)) != NULL) {
                if (strlen(ent->d_name) != 64 ||
                    strcmp(ent->d_name, junk_name_a) == 0 ||
                    strcmp(ent->d_name, junk_name_b) == 0)
                    continue;
                bool was_before = false;
                for (size_t i = 0; i < before_count; i++) {
                    if (strcmp(before_names[i], ent->d_name) == 0) {
                        was_before = true;
                        break;
                    }
                }
                if (!was_before) {
                    snprintf(real_path, sizeof(real_path), "%s/%s", evdir,
                             ent->d_name);
                    break; /* the one new name — deterministic regardless
                            * of enumeration order */
                }
            }
            if (ed)
                closedir(ed);
        }
        ZPY_CHECK("book: real event file found", real_path[0] != '\0');
        ZPY_CHECK("book: id-mismatch planted",
                  rename(real_path, junk_path) == 0);
    }
    book = vcs_service_book_load(zcode_dir);
    ZPY_CHECK("book: corrupt wires skipped and counted, facts intact",
              book != NULL && vcs_service_book_corrupt_count(book) == 2 &&
              vcs_service_key_totals(book, key_a, 20000, &kt) &&
              kt.verified_bytes_uploaded == 1048576 &&
              vcs_service_book_event_count(book) == events_before);
    vcs_service_book_free(book);
    zpy_rm_rf(zcode_dir);
    return failures;
}

/* ── 5. the typed commands over fixture datadirs ────────────────────── */

struct zpy_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void zpy_cmd_init(struct zpy_cmd *c, const char *datadir)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.zcode_policy_test.v1");
    if (datadir)
        (void)json_push_kv_str(&c->input, "datadir", datadir);
}

static void zpy_cmd_free(struct zpy_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* Reward-ledger helpers (the test_zcode_rank pattern). */
static void zpy_facts(uint8_t seed, uint8_t out[32])
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(0xf0 - seed - i);
    if (out[0] == 0)
        out[0] = 0xaa;
}

static enum vcs_reward_enqueue_error zpy_auto(
    struct vcs_reward_ledger *l, uint8_t root_seed,
    const uint8_t contributor[33], enum vcs_reward_category cat,
    uint32_t points, uint8_t facts_seed, uint8_t id_out[32])
{
    uint8_t root[32], facts[32];
    zpy_root(root_seed, root);
    zpy_facts(facts_seed, facts);
    return vcs_reward_enqueue_auto(l, root, contributor, cat, points,
                                   facts, id_out);
}

static enum vcs_reward_commit_error zpy_settle(struct vcs_reward_ledger *l,
                                               int64_t day)
{
    struct vcs_reward_plan plan;
    if (!vcs_reward_plan_build(l, day, &plan))
        return VCS_REWARD_COMMIT_IO;
    uint8_t plan_id[32];
    memcpy(plan_id, plan.plan_id, 32);
    enum vcs_reward_plan_persist_error perr =
        vcs_reward_plan_persist(l, &plan);
    vcs_reward_plan_free(&plan);
    if (perr != VCS_REWARD_PLAN_PERSIST_OK &&
        perr != VCS_REWARD_PLAN_PERSIST_DUPLICATE)
        return VCS_REWARD_COMMIT_IO;
    struct vcs_reward_commit_result result;
    char detail[256];
    return vcs_reward_commit(l, plan_id, &result, detail, sizeof(detail));
}

static int t_seed_commands(void)
{
    int failures = 0;
    char datadir[4400], zcode_dir[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zpy_cmd_%ld",
             (long)getpid());
    snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    zpy_rm_rf(datadir);
    ZPY_CHECK("commands: datadir created", zpy_mkdir_p(zcode_dir));

    /* One active key: verified up/down, one publish in the day-20000
     * week, one invalid-chunk offence, one no-credit fact; 150 settled
     * points make it an earned contributor. */
    uint8_t key[33], req1[32], req2[32], rel[32];
    zpy_pub(0x61, key);
    zpy_root(0x31, req1);
    zpy_root(0x32, req2);
    zpy_root(0x33, rel);
    {
        struct vcs_service_book *book = vcs_service_book_load(zcode_dir);
        ZPY_CHECK("commands: book fixture",
                  book &&
                  vcs_service_credit_upload(book, key, req1, 3145728,
                                            20000) == VCS_SERVICE_CREDIT_OK &&
                  vcs_service_credit_download(book, key, req2, 1048576,
                                              20000) == VCS_SERVICE_CREDIT_OK &&
                  vcs_service_record_publish(book, key, rel, 20000) ==
                      VCS_SERVICE_RECORD_OK &&
                  vcs_service_record_offence(
                      book, key, VCS_POLICY_OFFENCE_INVALID_CHUNK,
                      20000) == VCS_SERVICE_RECORD_OK &&
                  vcs_service_record_no_credit(
                      book, key, VCS_POLICY_NO_CREDIT_ANNOUNCEMENT, 128,
                      20000) == VCS_SERVICE_RECORD_OK);
        vcs_service_book_free(book);
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(zcode_dir);
        uint8_t id[32];
        ZPY_CHECK("commands: reward fixture settles",
                  l &&
                  zpy_auto(l, 0x41, key, VCS_REWARD_CATEGORY_NEW_PACKAGE,
                           150, 0x42, id) == VCS_REWARD_ENQUEUE_OK &&
                  zpy_settle(l, 20000) == VCS_REWARD_COMMIT_OK);
        vcs_reward_ledger_free(l);
    }

    /* zcode seed status: the row resolves the tier from earned score +
     * the local ratio, with usage against allowances. */
    {
        struct zpy_cmd c;
        zpy_cmd_init(&c, datadir);
        (void)json_push_kv_int(&c.input, "day", 20000);
        zcl_native_handle_zcode_seed_status(&c.request, &c.reply);
        const struct json_value *rows = json_get(&c.reply.data, "rows");
        const struct json_value *r0 = rows ? json_at(rows, 0) : NULL;
        ZPY_CHECK("seed status: one row rendered",
                  json_get_int(json_get(&c.reply.data, "rendered")) == 1 &&
                  r0 != NULL);
        ZPY_CHECK("seed status: facts + tier resolved",
                  r0 &&
                  json_get_int(json_get(r0, "verified_bytes_uploaded")) ==
                      3145728 &&
                  json_get_int(json_get(r0, "verified_bytes_downloaded")) ==
                      1048576 &&
                  json_get_int(json_get(r0, "ratio_milli")) == 3000 &&
                  json_get_int(json_get(r0, "earned_score")) == 150 &&
                  strcmp(json_get_str(json_get(r0, "tier")),
                         "earned-contributor") == 0);
        const struct json_value *usage =
            r0 ? json_get(r0, "usage") : NULL;
        const struct json_value *allow =
            r0 ? json_get(r0, "allowances") : NULL;
        ZPY_CHECK("seed status: usage vs allowances",
                  usage && allow &&
                  json_get_int(json_get(usage, "publishes_this_week")) ==
                      1 &&
                  json_get_int(json_get(usage, "offence_total")) == 1 &&
                  json_get_int(json_get(allow, "publish_per_week")) == 4 &&
                  json_get_int(json_get(allow, "pin_allowance_bytes")) ==
                      (int64_t)(UINT64_C(256) * 1024u * 1024u));
        const struct json_value *bookj = json_get(&c.reply.data, "book");
        ZPY_CHECK("seed status: book totals",
                  bookj &&
                  json_get_int(json_get(bookj, "keys")) == 1 &&
                  json_get_int(json_get(bookj, "corrupt_wires")) == 0 &&
                  json_get_int(json_get(bookj, "no_credit_bytes")) == 128);
        const struct json_value *table =
            json_get(&c.reply.data, "policy_table");
        const struct json_value *thresholds =
            table ? json_get(table, "thresholds") : NULL;
        ZPY_CHECK("seed status: the policy table is explicit",
                  thresholds &&
                  json_get_int(json_get(thresholds,
                                        "earned_contributor_min_score")) ==
                      100 &&
                  json_get_int(json_get(&c.reply.data, "week_start")) ==
                      19996);
        const struct json_value *nc =
            json_get(&c.reply.data, "never_earns_credit");
        ZPY_CHECK("seed status: the never-credit list is explicit",
                  nc && json_at(nc, 5) != NULL && json_at(nc, 6) == NULL);
        ZPY_CHECK("seed status: the locality note names no-global-mint",
                  strstr(json_get_str(
                             json_get(&c.reply.data, "locality_note")),
                         "no global ZCODE mint") != NULL);
        zpy_cmd_free(&c);
    }

    /* The pubkey filter adds the per-kind breakdowns. */
    {
        struct zpy_cmd c;
        zpy_cmd_init(&c, datadir);
        char hex[67];
        zpy_hex_enc(key, 33, hex);
        (void)json_push_kv_str(&c.input, "pubkey", hex);
        (void)json_push_kv_int(&c.input, "day", 20000);
        zcl_native_handle_zcode_seed_status(&c.request, &c.reply);
        const struct json_value *rows = json_get(&c.reply.data, "rows");
        const struct json_value *r0 = rows ? json_at(rows, 0) : NULL;
        const struct json_value *offs =
            r0 ? json_get(r0, "offences_by_kind") : NULL;
        const struct json_value *ncs =
            r0 ? json_get(r0, "no_credit_events_by_kind") : NULL;
        ZPY_CHECK("seed status: filtered detail names kinds",
                  json_get_bool(json_get(&c.reply.data, "key_known")) &&
                  offs &&
                  json_get_int(json_get(offs, "invalid-chunk")) == 1 &&
                  json_get_int(json_get(offs, "duplicate-request")) == 0 &&
                  ncs &&
                  json_get_int(json_get(ncs, "announcement-bytes")) == 1);
        zpy_cmd_free(&c);
    }
    {
        struct zpy_cmd c;
        zpy_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "pubkey", "zz");
        zcl_native_handle_zcode_seed_status(&c.request, &c.reply);
        ZPY_CHECK("seed status: BAD_PUBKEY names the input failure",
                  strcmp(c.reply.error.code, "BAD_PUBKEY") == 0);
        zpy_cmd_free(&c);
    }

    /* zcode seed ratio: the computation is stated explicitly. */
    {
        struct zpy_cmd c;
        zpy_cmd_init(&c, datadir);
        zcl_native_handle_zcode_seed_ratio(&c.request, &c.reply);
        const struct json_value *rows = json_get(&c.reply.data, "rows");
        const struct json_value *r0 = rows ? json_at(rows, 0) : NULL;
        ZPY_CHECK("seed ratio: rows + explicit computation",
                  r0 &&
                  json_get_int(json_get(r0, "ratio_milli")) == 3000 &&
                  json_get_int(json_get(r0, "no_credit_bytes")) == 128 &&
                  json_get_bool(json_get(&c.reply.data, "verified_only")) &&
                  strstr(json_get_str(json_get(&c.reply.data,
                                               "computed_as")),
                         "verified_bytes_uploaded * 1000") != NULL &&
                  json_get(&c.reply.data, "never_earns_credit") != NULL &&
                  strstr(json_get_str(json_get(&c.reply.data,
                                               "locality_note")),
                         "no global ZCODE mint") != NULL);
        zpy_cmd_free(&c);
    }
    zpy_rm_rf(datadir);
    return failures;
}

/* ── 6. storage status + the pin allowance against a REAL store ─────── */

/* Write <dir>/<path> content and add it to the manifest with the real
 * chunk hash (the test_zcode_publish pattern). */
static bool zpy_add_file(struct vcs_package_manifest *m, const char *dir,
                         const char *path, const char *content)
{
    char full[1024];
    snprintf(full, sizeof(full), "%s/%s", dir, path);
    const char *slash = strrchr(path, '/');
    if (slash) {
        char parent[1024];
        snprintf(parent, sizeof(parent), "%s/%.*s", dir,
                 (int)(slash - path), path);
        (void)mkdir(parent, 0700); /* EEXIST is fine */
    }
    FILE *f = fopen(full, "wb");
    if (!f)
        return false;
    size_t len = strlen(content);
    bool wrote = fwrite(content, 1, len, f) == len;
    fclose(f);
    if (!wrote)
        return false;
    uint8_t hash[32];
    if (!vcs_package_chunk_hash((const uint8_t *)content, len, hash))
        return false;
    return vcs_package_manifest_add(m, path, VCS_PACKAGE_MODE_FILE, len,
                                    hash, 1);
}

static int t_storage_commands(void)
{
    int failures = 0;

    /* No store: honest zero view without creating one. */
    char datadir[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zpy_store_%ld",
             (long)getpid());
    zpy_rm_rf(datadir);
    ZPY_CHECK("storage: datadir created", zpy_mkdir_p(datadir));
    {
        struct zpy_cmd c;
        zpy_cmd_init(&c, datadir);
        zcl_native_handle_zcode_storage_status(&c.request, &c.reply);
        const struct json_value *pools = json_get(&c.reply.data, "pools");
        const struct json_value *pins =
            pools ? json_get(pools, "pins") : NULL;
        const struct json_value *view =
            json_get(&c.reply.data, "policy_view");
        const struct json_value *tiers =
            view ? json_get(view, "tiers") : NULL;
        const struct json_value *nu =
            tiers ? json_get(tiers, "new-user") : NULL;
        ZPY_CHECK("storage: absent store reports honestly",
                  !json_get_bool(json_get(&c.reply.data,
                                          "store_present")) &&
                  pins &&
                  json_get_int(json_get(pins, "budget_bytes")) ==
                      2147483648LL /* 10 GiB * 2/10 */ &&
                  json_get_int(json_get(pins, "used_bytes")) == 0 &&
                  nu &&
                  json_get_int(json_get(nu, "pin_allowance_bytes")) == 0);
        zpy_cmd_free(&c);
        struct stat st;
        char zcode_dir[4400];
        snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
        ZPY_CHECK("storage: the read did not create a store",
                  stat(zcode_dir, &st) != 0);
    }

    /* A real store with one pinned package: the PINS pool usage feeds
     * the policy view, and the pure pin gate composes with it. */
    char pkgdir[4400];
    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg", datadir);
    struct vcs_package_manifest m;
    vcs_package_manifest_init(&m);
    ZPY_CHECK("storage: package fixture builds",
              zpy_mkdir_p(pkgdir) &&
              zpy_add_file(&m, pkgdir, "LICENSE",
                           "MIT License\n\nPermission is hereby granted.\n") &&
              zpy_add_file(&m, pkgdir, "src/ring.c",
                           "int ring_push(void) { return 0; }\n"));
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t root[32];
    ZPY_CHECK("storage: manifest serializes",
              vcs_package_manifest_serialize(&m, &wire, &wire_len) &&
              vcs_package_manifest_root(&m, root));
    struct vcs_package_store *store =
        vcs_package_store_open(datadir,
                               VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    ZPY_CHECK("storage: store opens", store != NULL);
    uint8_t stored_root[32];
    ZPY_CHECK("storage: manifest admitted",
              store &&
              vcs_package_store_put_manifest(store, wire, wire_len,
                                             stored_root) ==
                  VCS_PACKAGE_STORE_OK &&
              memcmp(stored_root, root, 32) == 0);
    bool chunks_ok = true;
    for (size_t i = 0; store && i < m.count; i++) {
        const struct vcs_package_file *f = &m.files[i];
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", pkgdir, f->path);
        FILE *ff = fopen(full, "rb");
        if (!ff) {
            chunks_ok = false;
            break;
        }
        uint8_t buf[256];
        size_t len = fread(buf, 1, sizeof(buf), ff);
        fclose(ff);
        if (vcs_package_store_put_chunk(store, root, f->path, 0, buf,
                                        len) != VCS_PACKAGE_STORE_OK)
            chunks_ok = false;
    }
    ZPY_CHECK("storage: chunks admitted (package complete)", chunks_ok);
    ZPY_CHECK("storage: operator pin succeeds",
              store &&
              vcs_package_store_pin(store, root, true) ==
                  VCS_PACKAGE_STORE_OK);
    uint64_t pins_used =
        store ? vcs_package_store_pool_usage(store,
                                             VCS_PACKAGE_STORE_POOL_PINS)
              : 0;
    ZPY_CHECK("storage: the PINS pool carries the package bytes",
              pins_used > 0);
    if (store)
        vcs_package_store_close(store);

    /* The pin-allowance gate against the REAL pool usage: a new user is
     * denied naming the rule; a contributor pins within the allowance. */
    struct vcs_policy_decision d =
        vcs_policy_check_pin(VCS_POLICY_TIER_NEW_USER, pins_used, 1);
    ZPY_CHECK("storage: a new user's pin request names the rule",
              !d.allow &&
              strcmp(d.rule, "pin-allowance-exceeded") == 0);
    ZPY_CHECK("storage: contributor pin within the allowance is allowed",
              vcs_policy_check_pin(VCS_POLICY_TIER_EARNED_CONTRIBUTOR,
                                   pins_used, 1024).allow &&
              !vcs_policy_check_pin(VCS_POLICY_TIER_EARNED_CONTRIBUTOR,
                                    pins_used,
                                    UINT64_C(256) * 1024u * 1024u).allow);

    {
        struct zpy_cmd c;
        zpy_cmd_init(&c, datadir);
        zcl_native_handle_zcode_storage_status(&c.request, &c.reply);
        const struct json_value *pools = json_get(&c.reply.data, "pools");
        const struct json_value *pins =
            pools ? json_get(pools, "pins") : NULL;
        const struct json_value *view =
            json_get(&c.reply.data, "policy_view");
        ZPY_CHECK("storage: live pool usage in the policy view",
                  json_get_bool(json_get(&c.reply.data,
                                         "store_present")) &&
                  pins &&
                  json_get_int(json_get(pins, "used_bytes")) ==
                      (int64_t)pins_used &&
                  view &&
                  json_get_int(json_get(view, "pins_pool_used_bytes")) ==
                      (int64_t)pins_used);
        zpy_cmd_free(&c);
    }
    free(wire);
    vcs_package_manifest_free(&m);
    zpy_rm_rf(datadir);
    return failures;
}

/* ── 7. the publish-frequency gate through the commit command ─────────
 * Full signed-release fixtures (the test_zcode_publish pattern). */

static bool zpyf_keypair(uint8_t seed, struct privkey *sk,
                         struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static bool zpyf_sign(struct vcs_package_release *r, struct privkey *sk)
{
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(r, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(sk, &hash, compact))
        return false;
    memcpy(r->signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    return true;
}

static bool zpyf_t1_reward(char *out, size_t out_size)
{
    const struct chain_params *params = chain_params_get();
    if (!params)
        return false;
    size_t pubkey_len = 0;
    size_t script_len = 0;
    const unsigned char *pubkey_prefix =
        chain_params_base58_prefix(params, B58_PUBKEY_ADDRESS, &pubkey_len);
    const unsigned char *script_prefix =
        chain_params_base58_prefix(params, B58_SCRIPT_ADDRESS, &script_len);
    if (!pubkey_prefix || !script_prefix)
        return false;
    struct tx_destination dest;
    dest.type = DEST_KEY_ID;
    memset(dest.id.key.id.data, 0x33, 20);
    return encode_destination(&dest, pubkey_prefix, pubkey_len,
                              script_prefix, script_len, out, out_size);
}

static char *zpyf_hex(const uint8_t *data, size_t len)
{
    static const char hexd[] = "0123456789abcdef";
    char *out = malloc(2 * len + 1);
    if (!out)
        return NULL;
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hexd[(data[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[data[i] & 0xf];
    }
    out[2 * len] = '\0';
    return out;
}

struct zpyf_pkg {
    struct vcs_package_manifest manifest;
    uint8_t *wire;
    size_t wire_len;
    uint8_t root[32];
    char *manifest_hex;  /* malloc */
    char *recipe_hex;    /* malloc */
    uint8_t recipe_root[32];
};

static void zpyf_pkg_free(struct zpyf_pkg *p)
{
    vcs_package_manifest_free(&p->manifest);
    free(p->wire);
    free(p->manifest_hex);
    free(p->recipe_hex);
    p->wire = NULL;
    p->manifest_hex = NULL;
    p->recipe_hex = NULL;
}

/* A valid package variant (LICENSE + include/zpy.h + src/zpy.c; the
 * variant byte changes the source, hence the root) with its declarative
 * recipe (slice 5: the envelope commits its root). */
static bool zpyf_make_pkg(struct zpyf_pkg *p, const char *dir,
                          unsigned variant)
{
    memset(p, 0, sizeof(*p));
    vcs_package_manifest_init(&p->manifest);
    (void)zpy_mkdir_p(dir);
    char src[160];
    snprintf(src, sizeof(src),
             "#include \"zpy.h\"\nint zpy_push(void) { return %u; }\n",
             variant);
    if (!zpy_add_file(&p->manifest, dir, "LICENSE",
                      "MIT License\n\nPermission is hereby granted.\n") ||
        !zpy_add_file(&p->manifest, dir, "include/zpy.h",
                      "#pragma once\nstruct zpy { unsigned head, tail; };\n") ||
        !zpy_add_file(&p->manifest, dir, "src/zpy.c", src))
        return false;
    if (!vcs_package_manifest_serialize(&p->manifest, &p->wire,
                                        &p->wire_len) ||
        !vcs_package_manifest_root(&p->manifest, p->root))
        return false;
    p->manifest_hex = zpyf_hex(p->wire, p->wire_len);
    if (!p->manifest_hex)
        return false;

    struct vcs_package_recipe r;
    vcs_package_recipe_init(&r);
    bool ok = vcs_package_recipe_add_header(&r, "include/zpy.h", NULL) &&
              vcs_package_recipe_add_include_dir(&r, "include", NULL) &&
              vcs_package_recipe_add_source(&r, "src/zpy.c", NULL) &&
              vcs_package_recipe_add_define(&r, "ZCL_FIXTURE=1", NULL) &&
              vcs_package_recipe_add_library(&r, VCS_PACKAGE_RECIPE_LIB_LIBC,
                                             NULL);
    vcs_package_recipe_set_test_limits(&r, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    uint8_t *rwire = NULL;
    size_t rwire_len = 0;
    if (ok)
        ok = vcs_package_recipe_root(&r, p->recipe_root) ==
                 VCS_PACKAGE_RECIPE_OK &&
             vcs_package_recipe_serialize(&r, &rwire, &rwire_len) ==
                 VCS_PACKAGE_RECIPE_OK;
    vcs_package_recipe_free(&r);
    if (!ok) {
        free(rwire);
        return false;
    }
    p->recipe_hex = zpyf_hex(rwire, rwire_len);
    free(rwire);
    return p->recipe_hex != NULL;
}

static bool zpyf_release(struct vcs_package_release *r, uint8_t key_seed,
                         uint64_t sequence, const char *name,
                         const struct zpyf_pkg *pkg)
{
    memset(r, 0, sizeof(*r));
    struct privkey sk;
    struct pubkey pk;
    if (!zpyf_keypair(key_seed, &sk, &pk))
        return false;
    r->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(r->name, sizeof(r->name), "%s", name);
    snprintf(r->semver, sizeof(r->semver), "1.0.0");
    memcpy(r->package_root, pkg->root, 32);
    r->has_parent = false;
    memcpy(r->publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    r->publisher_sequence = sequence;
    if (!zpyf_t1_reward(r->reward_address, sizeof(r->reward_address)))
        return false;
    snprintf(r->license, sizeof(r->license), "MIT");
    memcpy(r->recipe_root, pkg->recipe_root, 32);
    r->has_znam = false;
    if (!vcs_package_accept_chain_id(r->chain_id, sizeof(r->chain_id)))
        return false;
    return zpyf_sign(r, &sk);
}

/* Run zcode.package.publish.commit for one candidate at one day. The
 * release hex is malloc'd; the caller frees it. */
static void zpyf_commit(struct zpy_cmd *c, const char *datadir,
                        const struct zpyf_pkg *pkg,
                        const struct vcs_package_release *release,
                        const char *pkgdir, int64_t day)
{
    uint8_t *rwire = NULL;
    size_t rwire_len = 0;
    char *release_hex = NULL;
    if (vcs_package_release_serialize(release, &rwire, &rwire_len) ==
        VCS_PACKAGE_RELEASE_OK)
        release_hex = zpyf_hex(rwire, rwire_len);
    free(rwire);
    zpy_cmd_init(c, datadir);
    if (release_hex)
        (void)json_push_kv_str(&c->input, "release_hex", release_hex);
    (void)json_push_kv_str(&c->input, "manifest_hex", pkg->manifest_hex);
    (void)json_push_kv_str(&c->input, "recipe_hex", pkg->recipe_hex);
    (void)json_push_kv_str(&c->input, "dir", pkgdir);
    (void)json_push_kv_int(&c->input, "day", day);
    zcl_native_handle_zcode_package_publish_commit(&c->request, &c->reply);
    free(release_hex);
}

static int t_publish_gate(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char datadir[4400], zcode_dir[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zpy_gate_%ld",
             (long)getpid());
    snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    zpy_rm_rf(datadir);
    ZPY_CHECK("gate: datadir created", zpy_mkdir_p(zcode_dir));

    const uint8_t key_seed = 0x41;
    uint8_t pub[33];
    {
        struct privkey sk;
        struct pubkey pk;
        ZPY_CHECK("gate: publisher key derives",
                  zpyf_keypair(key_seed, &sk, &pk));
        memcpy(pub, pk.vch, 33);
    }

    /* A new user's FIRST publish in the week commits; the reply carries
     * the policy block (tier new-user, 1 publish this week). */
    struct zpyf_pkg p1;
    struct vcs_package_release r1;
    char pkg1[4400];
    snprintf(pkg1, sizeof(pkg1), "%s/pkg1", datadir);
    ZPY_CHECK("gate: candidate 1 builds",
              zpyf_make_pkg(&p1, pkg1, 1) &&
              zpyf_release(&r1, key_seed, 1, "zpy/ring1", &p1));
    {
        struct zpy_cmd c;
        zpyf_commit(&c, datadir, &p1, &r1, pkg1, 20000);
        const struct json_value *pol = json_get(&c.reply.data, "policy");
        ZPY_CHECK("gate: the first publish commits",
                  strcmp(json_get_str(json_get(&c.reply.data, "result")),
                         "committed") == 0 && c.reply.error.mutated);
        ZPY_CHECK("gate: the policy block reports the new-user tier",
                  pol &&
                  strcmp(json_get_str(json_get(pol, "tier")),
                         "new-user") == 0 &&
                  json_get_int(json_get(pol, "publishes_this_week")) == 1 &&
                  json_get_int(json_get(pol, "publish_per_week")) == 1 &&
                  json_get_bool(json_get(pol, "policy_recorded")));
        zpy_cmd_free(&c);
    }

    /* Idempotent recommit of the SAME release: acceptance classifies
     * DUPLICATE, the gate is skipped, and the result stays "duplicate"
     * even though the week's allowance is now exhausted. */
    {
        struct zpy_cmd c;
        zpyf_commit(&c, datadir, &p1, &r1, pkg1, 20000);
        ZPY_CHECK("gate: recommit stays an idempotent duplicate (gate "
                  "skipped)",
                  strcmp(json_get_str(json_get(&c.reply.data, "result")),
                         "duplicate") == 0 && !c.reply.error.mutated);
        zpy_cmd_free(&c);
    }

    /* The SECOND distinct publish in the same ISO week is rejected
     * naming the exact rule (the free allowance is 1/week). */
    struct zpyf_pkg p2;
    struct vcs_package_release r2;
    char pkg2[4400];
    snprintf(pkg2, sizeof(pkg2), "%s/pkg2", datadir);
    ZPY_CHECK("gate: candidate 2 builds",
              zpyf_make_pkg(&p2, pkg2, 2) &&
              zpyf_release(&r2, key_seed, 2, "zpy/ring2", &p2));
    {
        struct zpy_cmd c;
        zpyf_commit(&c, datadir, &p2, &r2, pkg2, 20001);
        ZPY_CHECK("gate: the 2nd publish in a week names the rule",
                  strcmp(c.reply.error.code, "PUBLISH_FREQUENCY_LIMIT") ==
                      0 &&
                  strstr(c.reply.error.evidence,
                         "publish-frequency-limit") != NULL &&
                  strstr(c.reply.error.evidence, "new-user") != NULL);
        zpy_cmd_free(&c);
    }

    /* The NEXT ISO week allows the same candidate (a rate limit, never
     * a permanent denial). */
    {
        struct zpy_cmd c;
        zpyf_commit(&c, datadir, &p2, &r2, pkg2, 20007);
        ZPY_CHECK("gate: the next ISO week publishes the same candidate",
                  strcmp(json_get_str(json_get(&c.reply.data, "result")),
                         "committed") == 0);
        zpy_cmd_free(&c);
    }

    /* Earn 100 settled points → the tier becomes earned-contributor
     * (4 publishes/week) — the tier transition moves the gate. */
    {
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(zcode_dir);
        uint8_t id[32];
        ZPY_CHECK("gate: the publisher's reward settles",
                  l &&
                  zpy_auto(l, 0x44, pub, VCS_REWARD_CATEGORY_NEW_PACKAGE,
                           100, 0x45, id) == VCS_REWARD_ENQUEUE_OK &&
                  zpy_settle(l, 19990) == VCS_REWARD_COMMIT_OK);
        vcs_reward_ledger_free(l);
    }
    struct zpyf_pkg p3, p4, p5, p6;
    struct vcs_package_release r3, r4, r5, r6;
    char pkg3[4400], pkg4[4400], pkg5[4400], pkg6[4400];
    snprintf(pkg3, sizeof(pkg3), "%s/pkg3", datadir);
    snprintf(pkg4, sizeof(pkg4), "%s/pkg4", datadir);
    snprintf(pkg5, sizeof(pkg5), "%s/pkg5", datadir);
    snprintf(pkg6, sizeof(pkg6), "%s/pkg6", datadir);
    ZPY_CHECK("gate: candidates 3-6 build",
              zpyf_make_pkg(&p3, pkg3, 3) &&
              zpyf_release(&r3, key_seed, 3, "zpy/ring3", &p3) &&
              zpyf_make_pkg(&p4, pkg4, 4) &&
              zpyf_release(&r4, key_seed, 4, "zpy/ring4", &p4) &&
              zpyf_make_pkg(&p5, pkg5, 5) &&
              zpyf_release(&r5, key_seed, 5, "zpy/ring5", &p5) &&
              zpyf_make_pkg(&p6, pkg6, 6) &&
              zpyf_release(&r6, key_seed, 6, "zpy/ring6", &p6));
    {
        struct zpy_cmd c;
        zpyf_commit(&c, datadir, &p3, &r3, pkg3, 20007);
        const struct json_value *pol = json_get(&c.reply.data, "policy");
        ZPY_CHECK("gate: contributor tier publishes #2 of the week",
                  strcmp(json_get_str(json_get(&c.reply.data, "result")),
                         "committed") == 0 && pol &&
                  strcmp(json_get_str(json_get(pol, "tier")),
                         "earned-contributor") == 0 &&
                  json_get_int(json_get(pol, "publish_per_week")) == 4);
        zpy_cmd_free(&c);
        zpyf_commit(&c, datadir, &p4, &r4, pkg4, 20008);
        ZPY_CHECK("gate: contributor tier publishes #3",
                  strcmp(json_get_str(json_get(&c.reply.data, "result")),
                         "committed") == 0);
        zpy_cmd_free(&c);
        zpyf_commit(&c, datadir, &p5, &r5, pkg5, 20009);
        ZPY_CHECK("gate: contributor tier publishes #4 (the allowance)",
                  strcmp(json_get_str(json_get(&c.reply.data, "result")),
                         "committed") == 0);
        zpy_cmd_free(&c);
        zpyf_commit(&c, datadir, &p6, &r6, pkg6, 20009);
        ZPY_CHECK("gate: #5 in the week names the rule at the "
                  "contributor tier",
                  strcmp(c.reply.error.code, "PUBLISH_FREQUENCY_LIMIT") ==
                      0 &&
                  strstr(c.reply.error.evidence,
                         "publish-frequency-limit") != NULL &&
                  strstr(c.reply.error.evidence,
                         "earned-contributor") != NULL &&
                  strstr(c.reply.error.evidence, "allowance=4") != NULL);
        zpy_cmd_free(&c);
    }

    /* The persisted facts agree: the service book holds exactly the 5
     * published events (r1..r5), never the rejected r6. */
    {
        struct vcs_service_book *book = vcs_service_book_load(zcode_dir);
        struct vcs_service_key_totals kt;
        ZPY_CHECK("gate: the service book holds exactly the published "
                  "events",
                  book &&
                  vcs_service_key_totals(book, pub, 20009, &kt) &&
                  kt.publish_events == 5 && kt.publishes_this_week == 4 &&
                  vcs_service_key_totals(book, pub, 20000, &kt) &&
                  kt.publishes_this_week == 1);
        vcs_service_book_free(book);
    }

    zpyf_pkg_free(&p1);
    zpyf_pkg_free(&p2);
    zpyf_pkg_free(&p3);
    zpyf_pkg_free(&p4);
    zpyf_pkg_free(&p5);
    zpyf_pkg_free(&p6);
    zpy_rm_rf(datadir);
    return failures;
}

/* ── service_receipt: dual-signed verified-byte codec ──────────────── */

static int t_service_receipt(void)
{
    int failures = 0;
    bool ok;
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    uint8_t up_secret[32] = {0};
    uint8_t down_secret[32] = {0};
    up_secret[31] = 0x21;
    down_secret[31] = 0x22;

    struct vcs_service_receipt r;
    memset(&r, 0, sizeof(r));
    size_t pub_len = 33;
    secp256k1_pubkey parsed;
    ok = secp256k1_ec_pubkey_create(ctx, &parsed, up_secret) == 1 &&
         secp256k1_ec_pubkey_serialize(ctx, r.uploader_pubkey, &pub_len,
                                       &parsed,
                                       SECP256K1_EC_COMPRESSED) == 1 &&
         pub_len == 33 &&
         secp256k1_ec_pubkey_create(ctx, &parsed, down_secret) == 1 &&
         secp256k1_ec_pubkey_serialize(ctx, r.downloader_pubkey,
                                       &pub_len, &parsed,
                                       SECP256K1_EC_COMPRESSED) == 1;
    for (size_t i = 0; i < VCS_SERVICE_RECEIPT_ROOT_BYTES; i++)
        r.package_root[i] = (uint8_t)(i * 5 + 1);
    r.verified_bytes = 1048576;
    r.day_start = 20600;
    r.day_end = 20606;
    for (size_t i = 0; i < VCS_SERVICE_RECEIPT_NONCE_BYTES; i++)
        r.session_nonce[i] = (uint8_t)(0xA0 ^ i);

    /* Deterministic id: same fields, same id; any field drift moves it. */
    {
        uint8_t id_a[32], id_b[32];
        vcs_service_receipt_id(&r, id_a);
        vcs_service_receipt_id(&r, id_b);
        ok = memcmp(id_a, id_b, 32) == 0;
        uint64_t saved = r.verified_bytes;
        r.verified_bytes = saved + 1;
        vcs_service_receipt_id(&r, id_b);
        ok = ok && memcmp(id_a, id_b, 32) != 0;
        r.verified_bytes = saved;
        vcs_service_receipt_id(&r, id_b);
        ok = ok && memcmp(id_a, id_b, 32) == 0;
    }
    ZPY_CHECK("receipt id is field-bound", ok);

    uint8_t wire[VCS_SERVICE_RECEIPT_WIRE_BYTES];
    ok = VCS_SERVICE_RECEIPT_WIRE_BYTES == 286 &&
         vcs_service_receipt_sign(&r, VCS_SERVICE_RECEIPT_UPLOADER, ctx,
                                  up_secret) ==
             VCS_SERVICE_RECEIPT_OK &&
         vcs_service_receipt_sign(&r, VCS_SERVICE_RECEIPT_DOWNLOADER,
                                  ctx, down_secret) ==
             VCS_SERVICE_RECEIPT_OK &&
         vcs_service_receipt_serialize(&r, wire, sizeof(wire)) ==
             VCS_SERVICE_RECEIPT_OK;

    struct vcs_service_receipt back;
    struct vcs_service_receipt swapped = r;
    struct vcs_service_receipt tampered = r;
    if (ok) {
        ok = vcs_service_receipt_verify(wire, sizeof(wire), &back) ==
                 VCS_SERVICE_RECEIPT_OK &&
             back.verified_bytes == 1048576 &&
             back.day_start == 20600 &&
             back.day_end == 20606 &&
             memcmp(back.uploader_pubkey, r.uploader_pubkey, 33) == 0;

        /* Swapped signatures must not verify: each key attests the id
         * for its own role only. */
        memcpy(swapped.uploader_signature, r.downloader_signature, 64);
        memcpy(swapped.downloader_signature, r.uploader_signature, 64);
        uint8_t sw[VCS_SERVICE_RECEIPT_WIRE_BYTES];
        ok = ok && vcs_service_receipt_serialize(&swapped, sw,
                                                 sizeof(sw)) ==
                        VCS_SERVICE_RECEIPT_OK &&
             vcs_service_receipt_verify(sw, sizeof(sw), NULL) ==
                 VCS_SERVICE_RECEIPT_ERR_SIG_VERIFY;

        /* Any tampered body byte breaks both signatures. */
        tampered.package_root[7] ^= 0x01;
        uint8_t tm[VCS_SERVICE_RECEIPT_WIRE_BYTES];
        ok = ok && vcs_service_receipt_serialize(&tampered, tm,
                                                 sizeof(tm)) ==
                        VCS_SERVICE_RECEIPT_OK &&
             vcs_service_receipt_verify(tm, sizeof(tm), NULL) ==
                 VCS_SERVICE_RECEIPT_ERR_SIG_VERIFY;
    }
    ZPY_CHECK("round-trip verify + swap/tamper refusals", ok);

    /* Grammar refusals name their rule. */
    struct vcs_service_receipt bad = r;
    uint8_t bw[VCS_SERVICE_RECEIPT_WIRE_BYTES];
    memcpy(bad.downloader_pubkey, bad.uploader_pubkey, 33);
    ok = vcs_service_receipt_serialize(&bad, bw, sizeof(bw)) ==
             VCS_SERVICE_RECEIPT_OK &&
         vcs_service_receipt_parse(bw, sizeof(bw), &back) ==
             VCS_SERVICE_RECEIPT_ERR_PUBKEY;
    ZPY_CHECK("grammar: equal keys refused", ok);

    bad = r;
    bad.verified_bytes = 0;
    ok = vcs_service_receipt_serialize(&bad, bw, sizeof(bw)) ==
             VCS_SERVICE_RECEIPT_OK &&
         vcs_service_receipt_parse(bw, sizeof(bw), &back) ==
             VCS_SERVICE_RECEIPT_ERR_ARGS;
    ZPY_CHECK("grammar: zero verified_bytes refused", ok);

    bad = r;
    bad.day_start = 20607;
    bad.day_end = 20606;
    ok = vcs_service_receipt_serialize(&bad, bw, sizeof(bw)) ==
             VCS_SERVICE_RECEIPT_OK &&
         vcs_service_receipt_parse(bw, sizeof(bw), &back) ==
             VCS_SERVICE_RECEIPT_ERR_ARGS;
    ZPY_CHECK("grammar: inverted day window refused", ok);

    bad = r;
    ok = vcs_service_receipt_serialize(&bad, bw, sizeof(bw)) ==
         VCS_SERVICE_RECEIPT_OK;
    memset(bw + 4 + 33 + 33 + 32 + 8 + 8 + 8, 0, 32);
    ok = ok && vcs_service_receipt_parse(bw, sizeof(bw), &back) ==
                 VCS_SERVICE_RECEIPT_ERR_ARGS;
    ZPY_CHECK("grammar: all-zero nonce refused", ok);

    ok = vcs_service_receipt_parse(wire, sizeof(wire) - 1, &back) ==
         VCS_SERVICE_RECEIPT_ERR_WIRE;
    {
        uint8_t magic[VCS_SERVICE_RECEIPT_WIRE_BYTES];
        memcpy(magic, wire, sizeof(magic));
        magic[0] = 'X';
        ok = ok && vcs_service_receipt_parse(magic, sizeof(magic),
                                             &back) ==
                    VCS_SERVICE_RECEIPT_ERR_WIRE;
    }
    ZPY_CHECK("grammar: wrong length / wrong magic refused", ok);

    secp256k1_context_destroy(ctx);
    return failures;
}

static int t_receipt_accept(void)
{
    int failures = 0;
    char zcode_dir[4400];
    snprintf(zcode_dir, sizeof(zcode_dir),
             "test-tmp/zpy_receipt_%ld/zcode", (long)getpid());
    zpy_rm_rf(zcode_dir);
    ZPY_CHECK("receipt-accept: datadir created", zpy_mkdir_p(zcode_dir));

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    uint8_t up_secret[32] = {0};
    uint8_t down_secret[32] = {0};
    uint8_t other_secret[32] = {0};
    up_secret[31] = 0x31;
    down_secret[31] = 0x32;
    other_secret[31] = 0x33;

    struct vcs_service_receipt r;
    memset(&r, 0, sizeof(r));
    size_t pub_len = 33;
    secp256k1_pubkey parsed;
    bool ok = secp256k1_ec_pubkey_create(ctx, &parsed, up_secret) == 1 &&
              secp256k1_ec_pubkey_serialize(ctx, r.uploader_pubkey, &pub_len,
                                            &parsed,
                                            SECP256K1_EC_COMPRESSED) == 1 &&
              secp256k1_ec_pubkey_create(ctx, &parsed, down_secret) == 1 &&
              secp256k1_ec_pubkey_serialize(ctx, r.downloader_pubkey,
                                            &pub_len, &parsed,
                                            SECP256K1_EC_COMPRESSED) == 1;
    uint8_t other_pub[33];
    pub_len = 33;
    ok = ok && secp256k1_ec_pubkey_create(ctx, &parsed, other_secret) == 1 &&
         secp256k1_ec_pubkey_serialize(ctx, other_pub, &pub_len, &parsed,
                                       SECP256K1_EC_COMPRESSED) == 1;
    for (size_t i = 0; i < VCS_SERVICE_RECEIPT_ROOT_BYTES; i++)
        r.package_root[i] = (uint8_t)(i + 3);
    r.verified_bytes = 4096;
    r.day_start = 20600;
    r.day_end = 20606;
    for (size_t i = 0; i < VCS_SERVICE_RECEIPT_NONCE_BYTES; i++)
        r.session_nonce[i] = (uint8_t)(0x5A ^ i);
    uint8_t wire[VCS_SERVICE_RECEIPT_WIRE_BYTES];
    ok = ok && vcs_service_receipt_sign(&r, VCS_SERVICE_RECEIPT_UPLOADER, ctx,
                                        up_secret) == VCS_SERVICE_RECEIPT_OK &&
         vcs_service_receipt_sign(&r, VCS_SERVICE_RECEIPT_DOWNLOADER, ctx,
                                  down_secret) == VCS_SERVICE_RECEIPT_OK &&
         vcs_service_receipt_serialize(&r, wire, sizeof(wire)) ==
             VCS_SERVICE_RECEIPT_OK;
    ZPY_CHECK("receipt-accept: signed wire", ok);

    struct vcs_service_book *book = vcs_service_book_load(zcode_dir);
    ZPY_CHECK("receipt-accept: book loads", book != NULL);
    if (!book) {
        secp256k1_context_destroy(ctx);
        return failures + 1;
    }

    ZPY_CHECK("receipt-accept: downloader credits upload counterpart",
              vcs_service_book_accept_receipt(book, wire, sizeof(wire),
                                              r.downloader_pubkey, 20603) ==
                  VCS_SERVICE_CREDIT_OK);
    struct vcs_service_key_totals kt;
    memset(&kt, 0, sizeof(kt));
    ok = vcs_service_key_totals(book, r.uploader_pubkey, 20603, &kt) &&
         kt.present && kt.verified_bytes_downloaded == 4096 &&
         kt.verified_bytes_uploaded == 0;
    ZPY_CHECK("receipt-accept: downloader book records received bytes", ok);

    ZPY_CHECK("receipt-accept: exact replay is duplicate",
              vcs_service_book_accept_receipt(book, wire, sizeof(wire),
                                              r.downloader_pubkey, 20603) ==
                  VCS_SERVICE_CREDIT_DUPLICATE);

    ZPY_CHECK("receipt-accept: uploader credits download counterpart",
              vcs_service_book_accept_receipt(book, wire, sizeof(wire),
                                              r.uploader_pubkey, 20603) ==
                  VCS_SERVICE_CREDIT_OK);
    memset(&kt, 0, sizeof(kt));
    ok = vcs_service_key_totals(book, r.downloader_pubkey, 20603, &kt) &&
         kt.present && kt.verified_bytes_uploaded == 4096 &&
         kt.verified_bytes_downloaded == 0;
    ZPY_CHECK("receipt-accept: uploader book records served bytes", ok);

    ZPY_CHECK("receipt-accept: stranger is not-party",
              vcs_service_book_accept_receipt(book, wire, sizeof(wire),
                                              other_pub, 20603) ==
                  VCS_SERVICE_CREDIT_NOT_PARTY);
    ZPY_CHECK("receipt-accept: day before window refused",
              vcs_service_book_accept_receipt(book, wire, sizeof(wire),
                                              r.downloader_pubkey, 20599) ==
                  VCS_SERVICE_CREDIT_WINDOW);
    ZPY_CHECK("receipt-accept: day after window refused",
              vcs_service_book_accept_receipt(book, wire, sizeof(wire),
                                              r.downloader_pubkey, 20607) ==
                  VCS_SERVICE_CREDIT_WINDOW);

    uint8_t bad[VCS_SERVICE_RECEIPT_WIRE_BYTES];
    memcpy(bad, wire, sizeof(bad));
    bad[20] ^= 0x01;
    ZPY_CHECK("receipt-accept: tampered wire unverified",
              vcs_service_book_accept_receipt(book, bad, sizeof(bad),
                                              r.downloader_pubkey, 20603) ==
                  VCS_SERVICE_CREDIT_UNVERIFIED);
    ZPY_CHECK("receipt-accept: named refusals",
              strcmp(vcs_service_credit_result_string(
                         VCS_SERVICE_CREDIT_NOT_PARTY),
                     "not-party") == 0 &&
                  strcmp(vcs_service_credit_result_string(
                             VCS_SERVICE_CREDIT_WINDOW),
                         "outside-window") == 0 &&
                  strcmp(vcs_service_credit_result_string(
                             VCS_SERVICE_CREDIT_UNVERIFIED),
                         "unverified-receipt") == 0);

    vcs_service_book_free(book);
    secp256k1_context_destroy(ctx);
    zpy_rm_rf(zcode_dir);
    return failures;
}

int test_zcode_policy(void)
{
    printf("\n=== zcode_policy: local P2P ratio + anti-spam policy ===\n");
    int failures = 0;
    failures += t_ratio();
    failures += t_tiers();
    failures += t_decisions();
    failures += t_book();
    failures += t_seed_commands();
    failures += t_service_receipt();
    failures += t_receipt_accept();
    failures += t_storage_commands();
    failures += t_publish_gate();
    printf("=== zcode_policy complete: %d failure(s) ===\n", failures);
    return failures;
}
