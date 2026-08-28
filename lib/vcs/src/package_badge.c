/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_badge — the ZCODE Badge codec, policy lens, durable badge
 * store, and plan/commit persistence primitives (slice 10). See
 * vcs/package_badge.h for the frozen contract (wire format, badge id,
 * store layout, dedup rule). This layer parses, serializes, hashes,
 * verifies, and persists only; signing happens outside (the command
 * handler signs through a callback) — private keys never enter lib/vcs.
 * Eligibility lives in package_badge_eligible.c. */

#include "vcs/package_badge.h"

#include "crypto/sha3.h"
#include "base/hex.h"
#include "platform/directory_compat.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "package_file_io.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include "vcs_priv.h"
#include "package_badge_priv.h"

#include <secp256k1.h>

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#define BADGE_LOG "vcs.badge"

static const uint8_t badge_wire_magic[VCS_PACKAGE_BADGE_WIRE_MAGIC_BYTES] =
    { 'Z', 'C', 'L', 'B', 'D', 'G', '\r', '\n' };
static const uint8_t badge_id_domain[] = VCS_PACKAGE_BADGE_ID_DOMAIN;

/* Plan wire magic + id domain (the commit wire magic lives with the
 * commit record in package_badge_commit.c). */
static const uint8_t badge_plan_magic[8] =
    { 'Z', 'C', 'L', 'B', 'P', 'L', '\r', '\n' };
static const uint8_t k_domain_plan[] = "zcl.zcode_badge_plan.v1";

/* The vendored libsecp256k1 archive does not export the
 * secp256k1_context_static symbol, so this layer keeps its own
 * verify-only context, created once at load time — the
 * package_release.c / package_attest.c pattern. */
static secp256k1_context *badge_verify_ctx;

__attribute__((constructor))
static void badge_verify_ctx_init(void)
{
    badge_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
}

__attribute__((destructor))
static void badge_verify_ctx_destroy(void)
{
    if (badge_verify_ctx)
        secp256k1_context_destroy(badge_verify_ctx);
}

/* secp256k1 group order half, n/2, big-endian: the low-S bound. */
static const uint8_t badge_half_order[32] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
};

/* ── type strings ───────────────────────────────────────────────────── */

const char *vcs_badge_type_string(enum vcs_badge_type type)
{
    switch (type) {
    case VCS_BADGE_FIRST_PACKAGE: return "first-package";
    case VCS_BADGE_TEN_PACKAGES: return "ten-packages";
    case VCS_BADGE_HUNDRED_TESTS: return "hundred-tests";
    case VCS_BADGE_BUG_HUNTER: return "bug-hunter";
    case VCS_BADGE_SECURITY_RESEARCHER: return "security-researcher";
    case VCS_BADGE_REPRODUCIBLE_BUILDER: return "reproducible-builder";
    case VCS_BADGE_TOP_DAILY: return "top-daily";
    case VCS_BADGE_TOP_WEEKLY: return "top-weekly";
    case VCS_BADGE_TOP_MONTHLY: return "top-monthly";
    case VCS_BADGE_ONE_YEAR_MAINTAINER: return "one-year-maintainer";
    case VCS_BADGE_POPULAR_PACKAGE: return "popular-package";
    case VCS_BADGE_RARE_PACKAGE_SEEDER: return "rare-package-seeder";
    case VCS_BADGE_EARLY_ZCODE_CONTRIBUTOR:
        return "early-zcode-contributor";
    case VCS_BADGE_TYPE_COUNT: break;
    }
    return "unknown";
}

bool vcs_badge_type_from_string(const char *name, enum vcs_badge_type *out)
{
    if (!name || !out)
        return false;
    for (size_t i = 0; i < VCS_BADGE_TYPE_COUNT; i++) {
        if (strcmp(name, vcs_badge_type_string((enum vcs_badge_type)i)) ==
            0) {
            *out = (enum vcs_badge_type)i;
            return true;
        }
    }
    return false;
}

bool vcs_badge_type_available(enum vcs_badge_type type)
{
    return type >= VCS_BADGE_FIRST_PACKAGE && type < VCS_BADGE_TYPE_COUNT &&
           type != VCS_BADGE_POPULAR_PACKAGE &&
           type != VCS_BADGE_RARE_PACKAGE_SEEDER;
}

bool vcs_badge_is_non_periodic(const struct vcs_badge *badge)
{
    return badge && badge->period_first_day == VCS_BADGE_PERIOD_NONE &&
           badge->period_last_day == VCS_BADGE_PERIOD_NONE;
}

/* ── small helpers ──────────────────────────────────────────────────── */

static bool badge_name_is_hex64(const char *name)
{
    uint8_t scratch[32];
    return zcl_hex_decode_lower(name, scratch, 32);
}

static bool badge_is_zero(const uint8_t *bytes, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (bytes[i] != 0)
            return false;
    return true;
}

static bool badge_pubkey_parses(const uint8_t pubkey[33])
{
    secp256k1_pubkey parsed;
    return secp256k1_ec_pubkey_parse(badge_verify_ctx, &parsed, pubkey, 33);
}

static bool badge_signature_low_s(const uint8_t signature[64])
{
    /* s is the second half, big-endian. */
    return memcmp(signature + 32, badge_half_order, 32) <= 0;
}

static void badge_put_i64le(uint8_t *p, int64_t v)
{
    vcs_wr_u64le(p, (uint64_t)v);
}

static int64_t badge_get_i64le(const uint8_t *p)
{
    return (int64_t)vcs_rd_u64le(p);
}

/* ── error strings ──────────────────────────────────────────────────── */

const char *vcs_badge_error_string(enum vcs_badge_error error)
{
    switch (error) {
    case VCS_BADGE_OK: return "ok";
    case VCS_BADGE_ERR_NULL: return "null-argument";
    case VCS_BADGE_ERR_ALLOC: return "allocation-failure";
    case VCS_BADGE_ERR_SCHEMA_VERSION: return "schema-version";
    case VCS_BADGE_ERR_WIRE_MAGIC: return "wire-magic";
    case VCS_BADGE_ERR_WIRE_OVERSIZE: return "wire-length";
    case VCS_BADGE_ERR_TYPE: return "badge-type";
    case VCS_BADGE_ERR_PERIOD: return "achievement-period";
    case VCS_BADGE_ERR_EVIDENCE_ROOT: return "evidence-root-zero";
    case VCS_BADGE_ERR_POLICY_ID: return "policy-id-zero";
    case VCS_BADGE_ERR_SEQUENCE: return "sequence-zero";
    case VCS_BADGE_ERR_RECIPIENT: return "recipient-pubkey";
    case VCS_BADGE_ERR_ISSUER: return "issuer-pubkey";
    case VCS_BADGE_ERR_SIG_LOW_S: return "signature-low-s";
    case VCS_BADGE_ERR_SIG_VERIFY: return "signature-verify";
    }
    return "unknown-error";
}

const char *vcs_badge_persist_error_string(
    enum vcs_badge_persist_error err)
{
    switch (err) {
    case VCS_BADGE_PERSIST_OK: return "ok";
    case VCS_BADGE_PERSIST_DUPLICATE: return "duplicate";
    case VCS_BADGE_PERSIST_FULL: return "store-full";
    case VCS_BADGE_PERSIST_INVALID: return "badge-invalid";
    case VCS_BADGE_PERSIST_IO: return "io-failure";
    }
    return "unknown-error";
}

/* ── the canonical body encoding (every field except the signature) ── */

#define BADGE_BODY_BYTES (VCS_PACKAGE_BADGE_WIRE_BYTES - 64u)

static void badge_body_encode(const struct vcs_badge *b,
                              uint8_t out[BADGE_BODY_BYTES])
{
    uint8_t *p = out;
    memcpy(p, badge_wire_magic, VCS_PACKAGE_BADGE_WIRE_MAGIC_BYTES);
    p += VCS_PACKAGE_BADGE_WIRE_MAGIC_BYTES;
    vcs_wr_u16le(p, b->schema_version);
    p += 2;
    p[0] = b->type;
    p++;
    memcpy(p, b->recipient, 33);
    p += 33;
    badge_put_i64le(p, b->period_first_day);
    p += 8;
    badge_put_i64le(p, b->period_last_day);
    p += 8;
    memcpy(p, b->evidence_root, 32);
    p += 32;
    memcpy(p, b->policy_id, 32);
    p += 32;
    vcs_wr_u64le(p, b->sequence);
    p += 8;
    memcpy(p, b->issuer_pubkey, 33);
    p += 33;
    (void)p;
}

enum vcs_badge_error vcs_badge_validate(const struct vcs_badge *badge)
{
    if (!badge)
        LOG_RETURN(VCS_BADGE_ERR_NULL, BADGE_LOG, "null validate");
    if (badge->schema_version != VCS_PACKAGE_BADGE_VERSION)
        return VCS_BADGE_ERR_SCHEMA_VERSION;
    if (badge->type >= VCS_BADGE_TYPE_COUNT)
        return VCS_BADGE_ERR_TYPE;
    if (!badge_pubkey_parses(badge->recipient))
        return VCS_BADGE_ERR_RECIPIENT;
    /* The period is the non-periodic sentinel as a PAIR, or an inclusive
     * civil-day range. Exactly one sentinel bound is non-canonical. */
    bool first_none = badge->period_first_day == VCS_BADGE_PERIOD_NONE;
    bool last_none = badge->period_last_day == VCS_BADGE_PERIOD_NONE;
    if (first_none != last_none)
        return VCS_BADGE_ERR_PERIOD;
    if (!first_none &&
        (badge->period_first_day < 0 ||
         badge->period_first_day > badge->period_last_day))
        return VCS_BADGE_ERR_PERIOD;
    if (badge_is_zero(badge->evidence_root, 32))
        return VCS_BADGE_ERR_EVIDENCE_ROOT;
    if (badge_is_zero(badge->policy_id, 32))
        return VCS_BADGE_ERR_POLICY_ID;
    if (badge->sequence == 0)
        return VCS_BADGE_ERR_SEQUENCE;
    if (!badge_pubkey_parses(badge->issuer_pubkey))
        return VCS_BADGE_ERR_ISSUER;
    return VCS_BADGE_OK;
}

enum vcs_badge_error vcs_badge_id(const struct vcs_badge *badge,
                                  uint8_t out[VCS_PACKAGE_BADGE_ID_BYTES])
{
    if (!badge || !out)
        LOG_RETURN(VCS_BADGE_ERR_NULL, BADGE_LOG, "null id");
    enum vcs_badge_error err = vcs_badge_validate(badge);
    if (err != VCS_BADGE_OK)
        return err;
    uint8_t body[BADGE_BODY_BYTES];
    badge_body_encode(badge, body);
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, badge_id_domain, sizeof(badge_id_domain));
    sha3_256_write(&ctx, body, sizeof(body));
    sha3_256_finalize(&ctx, out);
    return VCS_BADGE_OK;
}

enum vcs_badge_error vcs_badge_serialize(const struct vcs_badge *badge,
                                         uint8_t *out, size_t out_cap)
{
    if (!badge || !out)
        LOG_RETURN(VCS_BADGE_ERR_NULL, BADGE_LOG, "null serialize");
    if (out_cap < VCS_PACKAGE_BADGE_WIRE_BYTES)
        LOG_RETURN(VCS_BADGE_ERR_ALLOC, BADGE_LOG,
                   "serialize buffer %zu < %u", out_cap,
                   VCS_PACKAGE_BADGE_WIRE_BYTES);
    enum vcs_badge_error err = vcs_badge_validate(badge);
    if (err != VCS_BADGE_OK)
        return err;
    badge_body_encode(badge, out);
    memcpy(out + BADGE_BODY_BYTES, badge->signature, 64);
    return VCS_BADGE_OK;
}

enum vcs_badge_error vcs_badge_parse(const uint8_t *wire, size_t wire_len,
                                     struct vcs_badge *out)
{
    if (!wire || !out)
        LOG_RETURN(VCS_BADGE_ERR_NULL, BADGE_LOG, "null parse");
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_PACKAGE_BADGE_WIRE_BYTES)
        return VCS_BADGE_ERR_WIRE_OVERSIZE;
    if (memcmp(wire, badge_wire_magic, VCS_PACKAGE_BADGE_WIRE_MAGIC_BYTES) !=
        0)
        return VCS_BADGE_ERR_WIRE_MAGIC;
    const uint8_t *p = wire + VCS_PACKAGE_BADGE_WIRE_MAGIC_BYTES;
    out->schema_version = vcs_rd_u16le(p);
    p += 2;
    out->type = p[0];
    p++;
    memcpy(out->recipient, p, 33);
    p += 33;
    out->period_first_day = badge_get_i64le(p);
    p += 8;
    out->period_last_day = badge_get_i64le(p);
    p += 8;
    memcpy(out->evidence_root, p, 32);
    p += 32;
    memcpy(out->policy_id, p, 32);
    p += 32;
    out->sequence = vcs_rd_u64le(p);
    p += 8;
    memcpy(out->issuer_pubkey, p, 33);
    p += 33;
    memcpy(out->signature, p, 64);
    return vcs_badge_validate(out);
}

enum vcs_badge_error vcs_badge_verify(const struct vcs_badge *badge)
{
    if (!badge)
        LOG_RETURN(VCS_BADGE_ERR_NULL, BADGE_LOG, "null verify");
    enum vcs_badge_error err = vcs_badge_validate(badge);
    if (err != VCS_BADGE_OK)
        return err;
    if (!badge_signature_low_s(badge->signature))
        return VCS_BADGE_ERR_SIG_LOW_S;
    uint8_t id[VCS_PACKAGE_BADGE_ID_BYTES];
    err = vcs_badge_id(badge, id);
    if (err != VCS_BADGE_OK)
        return err;
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(badge_verify_ctx, &pubkey,
                                   badge->issuer_pubkey,
                                   VCS_PACKAGE_BADGE_PUBKEY_BYTES))
        return VCS_BADGE_ERR_ISSUER;
    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_signature_parse_compact(badge_verify_ctx,
                                                 &signature,
                                                 badge->signature))
        return VCS_BADGE_ERR_SIG_VERIFY;
    if (!secp256k1_ecdsa_verify(badge_verify_ctx, &signature, id, &pubkey))
        return VCS_BADGE_ERR_SIG_VERIFY;
    return VCS_BADGE_OK;
}

/* ── the policy lens ────────────────────────────────────────────────── */

bool vcs_badge_recognized(const struct vcs_badge *badge,
                          const struct vcs_badge_policy *policy)
{
    if (!badge || !policy)
        return false;
    return memcmp(badge->policy_id, policy->policy_id, 32) == 0 &&
           memcmp(badge->issuer_pubkey, policy->issuer_pubkey, 33) == 0;
}

bool vcs_badge_policy_load(const char *zcode_dir,
                           struct vcs_badge_policy *out)
{
    if (!zcode_dir || !out)
        LOG_RETURN(false, BADGE_LOG, "null policy load");
    memset(out, 0, sizeof(*out));
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/badge_policy", zcode_dir);
    if (n <= 0 || (size_t)n >= sizeof(path))
        LOG_RETURN(false, BADGE_LOG, "policy path too long");
    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERROR(BADGE_LOG, "badge policy %s: %s", path, strerror(errno));
        return false;
    }
    char lines[2][128];
    size_t count = 0;
    char buf[256];
    while (count < 2 && fgets(buf, sizeof(buf), f)) {
        char *s = buf;
        while (*s == ' ' || *s == '\t')
            s++;
        if (*s == '#' || *s == '\n' || *s == '\r' || *s == '\0')
            continue;
        size_t len = strcspn(s, "\r\n");
        if (len >= sizeof(lines[0])) {
            fclose(f);
            LOG_ERROR(BADGE_LOG, "badge policy line too long in %s", path);
            return false;
        }
        memcpy(lines[count], s, len);
        lines[count][len] = '\0';
        count++;
    }
    fclose(f);
    if (count != 2 || !zcl_hex_decode_lower(lines[0], out->policy_id, 32) ||
        !zcl_hex_decode_lower(lines[1], out->issuer_pubkey, 33) ||
        badge_is_zero(out->policy_id, 32) ||
        !badge_pubkey_parses(out->issuer_pubkey)) {
        LOG_ERROR(BADGE_LOG,
                  "badge policy %s malformed (want: 64-hex policy id, "
                  "66-hex issuer pubkey)", path);
        return false;
    }
    return true;
}

/* ── filesystem helpers (the package_store_io discipline) ───────────── */

bool badge_mkdir_p(const char *path)
{
#if defined(_WIN32)
    return platform_private_directory_ensure(path);
#else
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
#endif
}

/* Durable write: temp sibling + fsync + atomic rename. A crash leaves
 * either the old file or the new one, never a torn one. */
bool badge_atomic_write(const char *path, const uint8_t *data,
                        size_t data_len)
{
    static _Atomic uint64_t g_seq = 0;
    uint64_t seq = atomic_fetch_add(&g_seq, 1);
    char tmp[4400];
    int tn = snprintf(tmp, sizeof(tmp), "%s.tmp.%llu.%llu", path,
                      (unsigned long long)os_proc_current_pid(),
                      (unsigned long long)seq);
    if (tn <= 0 || (size_t)tn >= sizeof(tmp))
        LOG_FAIL(BADGE_LOG, "temp path too long for %s", path);
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool ok = platform_private_file_create(tmp, &file) &&
              platform_private_file_write_at(&file, data, data_len, 0) &&
              platform_private_file_truncate(&file, data_len) &&
              platform_private_file_flush(&file) &&
              platform_private_file_replace(&file, tmp, path);
    if (!ok) {
        platform_private_file_close(&file);
        (void)platform_private_file_unlink_missing_ok(tmp);
        LOG_FAIL(BADGE_LOG, "durable replace %s -> %s failed", tmp, path);
    }
    return true;
}

/* Read a whole bounded file. NULL when missing, empty, oversize, or
 * unreadable (missing is not an error: callers treat it as absent). */
uint8_t *badge_read_file(const char *path, size_t cap,
                         size_t *out_len)
{
    *out_len = 0;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot stamp;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &stamp)) {
        platform_positioned_file_close(&file);
        return NULL;
    }
    if (stamp.size == 0 || stamp.size > cap) {
        platform_positioned_file_close(&file);
        return NULL;
    }
    size_t len = (size_t)stamp.size;
    uint8_t *buf = zcl_malloc(len, "badge_read_file");
    if (!buf)
        LOG_NULL(BADGE_LOG, "alloc %zu for %s", len, path);
    if (platform_positioned_file_read(&file, buf, len, 0) != (int64_t)len) {
        platform_positioned_file_close(&file);
        free(buf);
        return NULL;
    }
    struct platform_positioned_file_snapshot after;
    bool stable = platform_positioned_file_snapshot(&file, &after) &&
                  vcs_package_file_snapshot_equal(&stamp, &after);
    platform_positioned_file_close(&file);
    if (!stable) { free(buf); return NULL; }
    *out_len = len;
    return buf;
}

static bool badge_file_exists(const char *path)
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    bool exists = platform_positioned_file_open(&file, path);
    platform_positioned_file_close(&file);
    return exists;
}

/* ── the store (struct vcs_badge_store and struct vcs_badge_loaded are
 *    defined in package_badge_priv.h, shared with package_badge_commit.c)
 *    ──────────────────────────────────────────────────────────────────── */

static int badge_id_cmp(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32);
}

static size_t badge_lower_bound(const uint8_t (*ids)[32], size_t count,
                                const uint8_t id[32], bool *found)
{
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (badge_id_cmp(ids[mid], id) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    *found = lo < count && badge_id_cmp(ids[lo], id) == 0;
    return lo;
}

/* Insert into a sorted id set; returns the slot index or (size_t)-1 on
 * allocation failure. *inserted is set true when the id was new. */
size_t badge_id_set_insert(uint8_t (**ids)[32], size_t *count,
                           size_t *cap, const uint8_t id[32],
                           bool *inserted)
{
    bool found = false;
    size_t at = badge_lower_bound(*ids, *count, id, &found);
    *inserted = !found;
    if (found)
        return at;
    if (*count == *cap) {
        size_t ncap = *cap ? *cap * 2 : 16;
        uint8_t (*nids)[32] =
            zcl_realloc(*ids, ncap * sizeof(*nids), "badge_id_set");
        if (!nids)
            LOG_RETURN((size_t)-1, BADGE_LOG, "id set grow to %zu", ncap);
        *ids = nids;
        *cap = ncap;
    }
    memmove(&(*ids)[at + 1], &(*ids)[at], (*count - at) * sizeof(*ids));
    memcpy((*ids)[at], id, 32);
    (*count)++;
    return at;
}

bool badge_id_set_contains(const uint8_t (*ids)[32], size_t count,
                           const uint8_t id[32])
{
    bool found = false;
    (void)badge_lower_bound(ids, count, id, &found);
    return found;
}

/* Register a verified badge in memory (ascending id order). */
static bool badge_store_register(struct vcs_badge_store *s,
                                 const struct vcs_badge *badge,
                                 const uint8_t id[32])
{
    bool found = false;
    size_t lo = 0, hi = s->badge_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (badge_id_cmp(s->badges[mid].id, id) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    found = lo < s->badge_count &&
            badge_id_cmp(s->badges[lo].id, id) == 0;
    if (found) /* identical id already loaded: dedup no-op */
        return true;
    if (s->badge_count == s->badge_cap) {
        size_t ncap = s->badge_cap ? s->badge_cap * 2 : 16;
        struct vcs_badge_loaded *nb =
            zcl_realloc(s->badges, ncap * sizeof(*nb), "badge_store_badges");
        if (!nb)
            LOG_RETURN(false, BADGE_LOG, "badge store grow to %zu", ncap);
        s->badges = nb;
        s->badge_cap = ncap;
    }
    memmove(&s->badges[lo + 1], &s->badges[lo],
            (s->badge_count - lo) * sizeof(*s->badges));
    s->badges[lo].badge = *badge;
    memcpy(s->badges[lo].id, id, 32);
    s->badge_count++;
    return true;
}

/* Scan one directory of 64-hex-named wires; cb consumes (name, wire,
 * len). Corrupt reads are counted by the caller. */
static void badge_scan_dir(struct vcs_badge_store *s, const char *dir,
                           size_t wire_cap, size_t max_files,
                           void (*cb)(struct vcs_badge_store *s,
                                      const char *name,
                                      const uint8_t *wire, size_t len))
{
    struct platform_directory_list list = {0};
    if (!platform_directory_list_regular_sorted(dir, &list))
        return; /* a missing dir is an empty store, never an error */
    size_t seen = 0;
    for (size_t entry = 0; entry < list.count; entry++) {
        const char *name = list.entries[entry].name;
        if (name[0] == '.')
            continue;
        if (strstr(name, ".tmp."))
            continue; /* a leftover atomic-write temp is never a valid
                         object (crash artifact, not corruption) */
        if (seen >= max_files) {
            s->truncated = true;
            LOG_ERROR(BADGE_LOG, "badge dir %s over bound %zu; truncated",
                      dir, max_files);
            break;
        }
        char path[4400];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
        if (n <= 0 || (size_t)n >= sizeof(path)) {
            s->corrupt++;
            continue;
        }
        seen++;
        size_t wire_len = 0;
        uint8_t *wire = badge_read_file(path, wire_cap, &wire_len);
        if (!wire) {
            s->corrupt++;
            LOG_ERROR(BADGE_LOG, "badge wire %s unreadable/oversize", path);
            continue;
        }
        cb(s, name, wire, wire_len);
        free(wire);
    }
    platform_directory_list_free(&list);
}

static void badge_load_one(struct vcs_badge_store *s, const char *name,
                           const uint8_t *wire, size_t len)
{
    struct vcs_badge badge;
    enum vcs_badge_error err = vcs_badge_parse(wire, len, &badge);
    if (err == VCS_BADGE_OK)
        err = vcs_badge_verify(&badge);
    if (err != VCS_BADGE_OK) {
        s->corrupt++;
        LOG_ERROR(BADGE_LOG, "badge wire %s rejected: %s", name,
                  vcs_badge_error_string(err));
        return;
    }
    uint8_t id[32];
    if (vcs_badge_id(&badge, id) != VCS_BADGE_OK) {
        s->corrupt++;
        return;
    }
    if (!badge_name_is_hex64(name)) {
        s->corrupt++;
        LOG_ERROR(BADGE_LOG, "badge wire %s: non-hex name", name);
        return;
    }
    uint8_t named[32];
    (void)zcl_hex_decode_lower(name, named, 32);
    if (badge_id_cmp(named, id) != 0) {
        s->corrupt++;
        LOG_ERROR(BADGE_LOG,
                  "badge wire %s commits a different id; rejected", name);
        return;
    }
    if (s->badge_count >= VCS_BADGE_MAX_BADGES) {
        s->truncated = true;
        return;
    }
    if (!badge_store_register(s, &badge, id))
        s->corrupt++;
}

static void badge_load_plan_id(struct vcs_badge_store *s, const char *name,
                               const uint8_t *wire, size_t len)
{
    (void)wire;
    (void)len; /* plan CONTENT is decoded on demand by vcs_badge_plan_read;
                  the load pass records the id set only */
    uint8_t id[32];
    if (!zcl_hex_decode_lower(name, id, 32)) {
        s->corrupt++;
        return;
    }
    bool inserted = false;
    if (badge_id_set_insert(&s->plans, &s->plan_count, &s->plan_cap, id,
                            &inserted) == (size_t)-1)
        s->corrupt++;
}

static void badge_load_commit_id(struct vcs_badge_store *s,
                                 const char *name, const uint8_t *wire,
                                 size_t len)
{
    (void)wire;
    (void)len;
    uint8_t id[32];
    if (!zcl_hex_decode_lower(name, id, 32)) {
        s->corrupt++;
        return;
    }
    bool inserted = false;
    if (badge_id_set_insert(&s->commits, &s->commit_count, &s->commit_cap,
                            id, &inserted) == (size_t)-1)
        s->corrupt++;
}

struct vcs_badge_store *vcs_badge_store_load(const char *zcode_dir)
{
    if (!zcode_dir)
        LOG_RETURN(NULL, BADGE_LOG, "null zcode_dir");
    struct vcs_badge_store *s = zcl_calloc(1, sizeof(*s), "badge_store");
    if (!s)
        LOG_NULL(BADGE_LOG, "alloc badge store");
    int n = snprintf(s->root, sizeof(s->root), "%s/badges", zcode_dir);
    if (n <= 0 || (size_t)n >= sizeof(s->root)) {
        free(s);
        LOG_RETURN(NULL, BADGE_LOG, "badge store path too long");
    }
    char dir[4400];
    (void)snprintf(dir, sizeof(dir), "%s", s->root);
    badge_scan_dir(s, dir, VCS_PACKAGE_BADGE_WIRE_BYTES,
                   VCS_BADGE_MAX_BADGES, badge_load_one);
    int dn = snprintf(dir, sizeof(dir), "%s/plans", s->root);
    if (dn > 0 && (size_t)dn < sizeof(dir))
        badge_scan_dir(s, dir, VCS_BADGE_MAX_PLAN_WIRE_BYTES,
                       VCS_BADGE_MAX_PLANS, badge_load_plan_id);
    dn = snprintf(dir, sizeof(dir), "%s/commits", s->root);
    if (dn > 0 && (size_t)dn < sizeof(dir))
        badge_scan_dir(s, dir, VCS_BADGE_MAX_COMMIT_WIRE_BYTES,
                       VCS_BADGE_MAX_COMMITS, badge_load_commit_id);
    return s;
}

void vcs_badge_store_free(struct vcs_badge_store *s)
{
    if (!s)
        return;
    free(s->badges);
    free(s->plans);
    free(s->commits);
    free(s);
}

size_t vcs_badge_store_badge_count(const struct vcs_badge_store *s)
{
    return s ? s->badge_count : 0;
}

uint32_t vcs_badge_store_corrupt_count(const struct vcs_badge_store *s)
{
    return s ? s->corrupt : 0;
}

bool vcs_badge_store_truncated(const struct vcs_badge_store *s)
{
    return s && s->truncated;
}

const struct vcs_badge *vcs_badge_store_at(const struct vcs_badge_store *s,
                                           size_t index)
{
    if (!s || index >= s->badge_count)
        return NULL;
    return &s->badges[index].badge;
}

void vcs_badge_store_id_at(const struct vcs_badge_store *s, size_t index,
                           uint8_t out[32])
{
    if (!s || !out || index >= s->badge_count) {
        if (out)
            memset(out, 0, 32);
        return;
    }
    memcpy(out, s->badges[index].id, 32);
}

const struct vcs_badge *vcs_badge_store_find(
    const struct vcs_badge_store *s, const uint8_t badge_id[32])
{
    if (!s || !badge_id)
        return NULL;
    bool found = false;
    size_t lo = 0, hi = s->badge_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (badge_id_cmp(s->badges[mid].id, badge_id) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    found = lo < s->badge_count &&
            badge_id_cmp(s->badges[lo].id, badge_id) == 0;
    return found ? &s->badges[lo].badge : NULL;
}

bool vcs_badge_store_dedup_hit(const struct vcs_badge_store *s,
                               const struct vcs_badge_policy *policy,
                               const uint8_t contributor[33],
                               enum vcs_badge_type type,
                               int64_t period_first, int64_t period_last)
{
    if (!s || !policy || !contributor)
        return false;
    for (size_t i = 0; i < s->badge_count; i++) {
        const struct vcs_badge *b = &s->badges[i].badge;
        if (b->type == (uint8_t)type &&
            b->period_first_day == period_first &&
            b->period_last_day == period_last &&
            memcmp(b->recipient, contributor, 33) == 0 &&
            vcs_badge_recognized(b, policy))
            return true;
    }
    return false;
}

uint64_t vcs_badge_store_max_sequence(const struct vcs_badge_store *s,
                                      const uint8_t issuer_pubkey[33])
{
    if (!s || !issuer_pubkey)
        return 0;
    uint64_t max_seq = 0;
    for (size_t i = 0; i < s->badge_count; i++) {
        const struct vcs_badge *b = &s->badges[i].badge;
        if (memcmp(b->issuer_pubkey, issuer_pubkey, 33) == 0 &&
            b->sequence > max_seq)
            max_seq = b->sequence;
    }
    return max_seq;
}

size_t vcs_badge_store_contributor_badges(
    const struct vcs_badge_store *s, const struct vcs_badge_policy *policy,
    const uint8_t contributor[33], struct vcs_badge *out, size_t cap)
{
    if (!s || !policy || !contributor)
        return 0;
    /* Selection sort by (sequence, badge id) over the recognized set —
     * the store is ascending by id, so a stable pass ordering by
     * sequence yields issuance order deterministically. */
    size_t total = 0;
    for (size_t i = 0; i < s->badge_count; i++) {
        const struct vcs_badge *b = &s->badges[i].badge;
        if (memcmp(b->recipient, contributor, 33) == 0 &&
            vcs_badge_recognized(b, policy))
            total++;
    }
    if (!out || cap == 0)
        return total;
    size_t written = 0;
    uint64_t last_seq = 0;
    bool have_last = false;
    while (written < cap && written < total) {
        const struct vcs_badge *best = NULL;
        const uint8_t *best_id = NULL;
        for (size_t i = 0; i < s->badge_count; i++) {
            const struct vcs_badge *b = &s->badges[i].badge;
            if (memcmp(b->recipient, contributor, 33) != 0 ||
                !vcs_badge_recognized(b, policy))
                continue;
            if (have_last && b->sequence <= last_seq)
                continue;
            if (!best || b->sequence < best->sequence ||
                (b->sequence == best->sequence &&
                 badge_id_cmp(s->badges[i].id, best_id) < 0)) {
                best = b;
                best_id = s->badges[i].id;
            }
        }
        if (!best)
            break;
        out[written++] = *best;
        last_seq = best->sequence;
        have_last = true;
    }
    return total;
}

/* ── persist one signed badge ───────────────────────────────────────── */

enum vcs_badge_persist_error vcs_badge_store_persist(
    struct vcs_badge_store *s, const struct vcs_badge *badge,
    uint8_t id_out[32])
{
    if (!s || !badge)
        return VCS_BADGE_PERSIST_IO;
    uint8_t id[32];
    if (vcs_badge_id(badge, id) != VCS_BADGE_OK ||
        vcs_badge_verify(badge) != VCS_BADGE_OK)
        return VCS_BADGE_PERSIST_INVALID;
    if (id_out)
        memcpy(id_out, id, 32);
    if (vcs_badge_store_find(s, id))
        return VCS_BADGE_PERSIST_DUPLICATE;
    if (s->badge_count >= VCS_BADGE_MAX_BADGES)
        return VCS_BADGE_PERSIST_FULL;

    if (!badge_mkdir_p(s->root)) {
        LOG_ERROR(BADGE_LOG, "mkdir %s: %s", s->root, strerror(errno));
        return VCS_BADGE_PERSIST_IO;
    }
    char id_hex[65];
    zcl_hex_encode(id, 32, id_hex);
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/%s", s->root, id_hex);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        LOG_ERROR(BADGE_LOG, "badge path too long");
        return VCS_BADGE_PERSIST_IO;
    }
    if (!vcs_package_file_exists(path)) {
        uint8_t wire[VCS_PACKAGE_BADGE_WIRE_BYTES];
        if (vcs_badge_serialize(badge, wire, sizeof(wire)) !=
                VCS_BADGE_OK ||
            !badge_atomic_write(path, wire, sizeof(wire)))
            return VCS_BADGE_PERSIST_IO;
    } /* else: the identical wire is already durable (a crash replay) */
    if (!badge_store_register(s, badge, id))
        return VCS_BADGE_PERSIST_IO;
    return VCS_BADGE_PERSIST_OK;
}

/* ── the issuance plan ──────────────────────────────────────────────── */

#define BADGE_PLAN_ROW_WIRE_BYTES (33u + 1u + 8u + 8u + 32u + 8u)
#define BADGE_PLAN_HEADER_BYTES (8u + 2u + 32u + 33u + 8u + 4u)

static int badge_plan_row_cmp(const void *a, const void *b)
{
    const struct vcs_badge_plan_row *ra = a;
    const struct vcs_badge_plan_row *rb = b;
    int c = memcmp(ra->contributor, rb->contributor, 33);
    if (c != 0)
        return c;
    if (ra->type != rb->type)
        return (int)ra->type - (int)rb->type;
    if (ra->period_first != rb->period_first)
        return ra->period_first < rb->period_first ? -1 : 1;
    if (ra->period_last != rb->period_last)
        return ra->period_last < rb->period_last ? -1 : 1;
    if (ra->sequence != rb->sequence)
        return ra->sequence < rb->sequence ? -1 : 1;
    return 0;
}

static size_t badge_plan_wire_bytes(size_t row_count)
{
    return BADGE_PLAN_HEADER_BYTES + row_count * BADGE_PLAN_ROW_WIRE_BYTES;
}

static void badge_plan_wire_encode(const struct vcs_badge_plan *plan,
                                   uint8_t *out)
{
    uint8_t *p = out;
    memcpy(p, badge_plan_magic, 8);
    p += 8;
    vcs_wr_u16le(p, VCS_PACKAGE_BADGE_VERSION);
    p += 2;
    memcpy(p, plan->policy_id, 32);
    p += 32;
    memcpy(p, plan->issuer_pubkey, 33);
    p += 33;
    badge_put_i64le(p, plan->planned_day);
    p += 8;
    vcs_wr_u32le(p, (uint32_t)plan->row_count);
    p += 4;
    for (size_t i = 0; i < plan->row_count; i++) {
        const struct vcs_badge_plan_row *r = &plan->rows[i];
        memcpy(p, r->contributor, 33);
        p += 33;
        p[0] = (uint8_t)r->type;
        p++;
        badge_put_i64le(p, r->period_first);
        p += 8;
        badge_put_i64le(p, r->period_last);
        p += 8;
        memcpy(p, r->evidence_root, 32);
        p += 32;
        vcs_wr_u64le(p, r->sequence);
        p += 8;
    }
}

static bool badge_plan_wire_decode(const uint8_t *wire, size_t len,
                                   struct vcs_badge_plan *out)
{
    memset(out, 0, sizeof(*out));
    if (len < BADGE_PLAN_HEADER_BYTES ||
        len > VCS_BADGE_MAX_PLAN_WIRE_BYTES ||
        (len - BADGE_PLAN_HEADER_BYTES) % BADGE_PLAN_ROW_WIRE_BYTES != 0)
        return false;
    if (memcmp(wire, badge_plan_magic, 8) != 0)
        return false;
    const uint8_t *p = wire + 8;
    if (vcs_rd_u16le(p) != VCS_PACKAGE_BADGE_VERSION)
        return false;
    p += 2;
    memcpy(out->policy_id, p, 32);
    p += 32;
    memcpy(out->issuer_pubkey, p, 33);
    p += 33;
    out->planned_day = badge_get_i64le(p);
    p += 8;
    uint32_t rows = vcs_rd_u32le(p);
    p += 4;
    if (rows > VCS_BADGE_MAX_PLAN_ROWS ||
        badge_plan_wire_bytes(rows) != len)
        return false;
    out->row_count = rows;
    for (size_t i = 0; i < out->row_count; i++) {
        struct vcs_badge_plan_row *r = &out->rows[i];
        memcpy(r->contributor, p, 33);
        p += 33;
        r->type = (enum vcs_badge_type)p[0];
        p++;
        r->period_first = badge_get_i64le(p);
        p += 8;
        r->period_last = badge_get_i64le(p);
        p += 8;
        memcpy(r->evidence_root, p, 32);
        p += 32;
        r->sequence = vcs_rd_u64le(p);
        p += 8;
        if (r->type >= VCS_BADGE_TYPE_COUNT || r->sequence == 0)
            return false;
    }
    return true;
}

static void badge_plan_id_compute(const struct vcs_badge_plan *plan,
                                  uint8_t out[32])
{
    /* The largest plan wire is ~23 KiB (VCS_BADGE_MAX_PLAN_ROWS bounded):
     * one stack buffer, no allocation, no fallback. */
    uint8_t wire[BADGE_PLAN_HEADER_BYTES +
                 VCS_BADGE_MAX_PLAN_ROWS * BADGE_PLAN_ROW_WIRE_BYTES];
    size_t wire_len = badge_plan_wire_bytes(plan->row_count);
    badge_plan_wire_encode(plan, wire);
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, k_domain_plan, sizeof(k_domain_plan) - 1u);
    sha3_256_write(&c, wire, wire_len);
    sha3_256_finalize(&c, out);
}

bool vcs_badge_plan_assemble(const uint8_t policy_id[32],
                             const uint8_t issuer_pubkey[33],
                             int64_t planned_day,
                             const struct vcs_badge_plan_row *rows,
                             size_t row_count, struct vcs_badge_plan *out)
{
    if (!policy_id || !issuer_pubkey || !out ||
        (row_count > 0 && !rows))
        LOG_RETURN(false, BADGE_LOG, "null plan assemble");
    if (row_count > VCS_BADGE_MAX_PLAN_ROWS)
        LOG_RETURN(false, BADGE_LOG, "plan rows %zu over bound %u",
                   row_count, (unsigned)VCS_BADGE_MAX_PLAN_ROWS);
    if (planned_day < 0)
        LOG_RETURN(false, BADGE_LOG, "negative planned day %lld",
                   (long long)planned_day);
    if (badge_is_zero(policy_id, 32) ||
        !badge_pubkey_parses(issuer_pubkey))
        LOG_RETURN(false, BADGE_LOG, "bad policy id or issuer key");
    memset(out, 0, sizeof(*out));
    memcpy(out->policy_id, policy_id, 32);
    memcpy(out->issuer_pubkey, issuer_pubkey, 33);
    out->planned_day = planned_day;
    out->row_count = row_count;
    for (size_t i = 0; i < row_count; i++) {
        if (rows[i].type >= VCS_BADGE_TYPE_COUNT ||
            rows[i].sequence == 0 ||
            badge_is_zero(rows[i].evidence_root, 32))
            LOG_RETURN(false, BADGE_LOG,
                       "plan row %zu invalid (type/sequence/evidence)", i);
        out->rows[i] = rows[i];
    }
    qsort(out->rows, out->row_count, sizeof(out->rows[0]),
          badge_plan_row_cmp);
    /* The canonical order forbids exact duplicate rows. */
    for (size_t i = 1; i < out->row_count; i++)
        if (badge_plan_row_cmp(&out->rows[i - 1], &out->rows[i]) == 0)
            LOG_RETURN(false, BADGE_LOG, "duplicate plan row %zu", i);
    badge_plan_id_compute(out, out->plan_id);
    return true;
}

enum vcs_badge_plan_persist_error vcs_badge_plan_persist(
    struct vcs_badge_store *s, const struct vcs_badge_plan *plan)
{
    if (!s || !plan)
        return VCS_BADGE_PLAN_PERSIST_IO;
    char dir[4400];
    int dn = snprintf(dir, sizeof(dir), "%s/plans", s->root);
    if (dn <= 0 || (size_t)dn >= sizeof(dir))
        return VCS_BADGE_PLAN_PERSIST_IO;
    if (!badge_mkdir_p(dir)) {
        LOG_ERROR(BADGE_LOG, "mkdir %s: %s", dir, strerror(errno));
        return VCS_BADGE_PLAN_PERSIST_IO;
    }
    char id_hex[65];
    zcl_hex_encode(plan->plan_id, 32, id_hex);
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, id_hex);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        LOG_ERROR(BADGE_LOG, "plan path too long");
        return VCS_BADGE_PLAN_PERSIST_IO;
    }
    if (vcs_package_file_exists(path))
        return VCS_BADGE_PLAN_PERSIST_DUPLICATE;
    if (s->plan_count >= VCS_BADGE_MAX_PLANS)
        return VCS_BADGE_PLAN_PERSIST_FULL;

    size_t wire_len = badge_plan_wire_bytes(plan->row_count);
    uint8_t *wire = zcl_malloc(wire_len, "badge_plan_wire");
    if (!wire) {
        LOG_ERROR(BADGE_LOG, "alloc %zu plan wire", wire_len);
        return VCS_BADGE_PLAN_PERSIST_IO;
    }
    badge_plan_wire_encode(plan, wire);
    bool ok = badge_atomic_write(path, wire, wire_len);
    free(wire);
    if (!ok)
        return VCS_BADGE_PLAN_PERSIST_IO;
    bool inserted = false;
    if (badge_id_set_insert(&s->plans, &s->plan_count, &s->plan_cap,
                            plan->plan_id, &inserted) == (size_t)-1)
        return VCS_BADGE_PLAN_PERSIST_IO;
    return VCS_BADGE_PLAN_PERSIST_OK;
}

int vcs_badge_plan_read(const struct vcs_badge_store *s,
                        const uint8_t plan_id[32],
                        struct vcs_badge_plan *out)
{
    if (!s || !plan_id || !out)
        return -1;
    char id_hex[65];
    zcl_hex_encode(plan_id, 32, id_hex);
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/plans/%s", s->root, id_hex);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return -1;
    size_t wire_len = 0;
    uint8_t *wire =
        badge_read_file(path, VCS_BADGE_MAX_PLAN_WIRE_BYTES, &wire_len);
    if (!wire)
        return 1; /* UNKNOWN_PLAN */
    if (!badge_plan_wire_decode(wire, wire_len, out)) {
        free(wire);
        LOG_ERROR(BADGE_LOG, "plan wire %s undecodable", id_hex);
        return -1;
    }
    free(wire);
    uint8_t computed[32];
    badge_plan_id_compute(out, computed);
    if (badge_id_cmp(computed, plan_id) != 0) {
        LOG_ERROR(BADGE_LOG, "plan wire %s commits a different id", id_hex);
        return -1;
    }
    return 0;
}

/* ── the commit record (the issuance idempotence authority) now lives in
 *    package_badge_commit.c, sharing this file's store shape and
 *    filesystem/id-set primitives through package_badge_priv.h ───────── */
