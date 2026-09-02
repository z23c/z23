/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_verify — the external-verifier attestation gate (slice 6:
 * contexts/commons/modules/vcs/package_attest.*, contexts/commons/modules/vcs/package_verify_policy.*, the
 * zcode package verify handler in tools/command/native_zcode_command.c,
 * and the build/bin/zclassic23-package-verify external program).
 *
 * Coverage:
 *   1. Attestation codec: roundtrip for every result class, a frozen KAT
 *      attestation id (canonical-encoding drift guard), every bound and
 *      consistency rule (closed grammar: magic/version/truncated/trailing/
 *      oversize wires, order rules, detail/class/test/sanitizer
 *      consistency), invalid signature, high-S malleation, wrong key.
 *   2. Approved-verifier policy: allowlist text parsing (comments, blanks,
 *      bad lines with line numbers, duplicates, the 64-key bound,
 *      off-curve keys) and the quorum rule — 2-of-N approved matching
 *      verifies; unapproved keys, self-verification, duplicate signers,
 *      and non-matching attestations are all named and never counted;
 *      a quorum on a FAIL class is not "verified".
 *   3. zcode package verify: verified quorum report over a fixture store,
 *      NO_APPROVED_VERIFIERS without the local allowlist, UNKNOWN_PACKAGE,
 *      BAD_ROOT, and the not-quite-quorum states; plus the reproduction
 *      object (two distinct matching receipts reproduce; a diverging
 *      receipt is named by rule).
 *   3b. Bit-identical reproduction (contexts/commons/modules/vcs/package_reproduce.*): the
 *      comparator (MATCH; every named divergence rule; the detail names
 *      the path and hashes), the receipts-directory scan (distinct build
 *      events agreeing byte-for-byte reproduce; one receipt does not; a
 *      tampered output is reported loudly), and the eligibility gates
 *      passing on a recorded reproduction with no quorum at all.
 *   3c. zcode package attest import: a signed wire files into
 *      attestations/ through the handler (idempotent re-import), verify
 *      then counts the imported wires, a tampered wire is refused naming
 *      the signature rule, a non-canonical wire names the parse rule, and
 *      an unseen package's attestation still files (filing is not
 *      acceptance — verify names UNKNOWN_PACKAGE).
 *   3d. The zcode package attest offer/pull COMMAND layer (the transport
 *      library itself is test_zcode_attest_transport's): offer returns
 *      BOTH the provider and the pointer publish input — publishing one
 *      without the other is a silent no-op at pull time — over a
 *      transport root that equals the blob root of the exact wire, is
 *      idempotent, and names ATTESTATION_ABSENT / BAD_ATTESTATION_ID;
 *      pull keeps NO_ATTESTATION_POINTERS and
 *      ATTESTATION_BYTES_UNREACHABLE distinct, and one hostile pointer
 *      (a binding mismatch) plus one unheld root do NOT abort the sweep
 *      — the honest verifier's attestation still lands filed while both
 *      failures stay in the rows naming their rule, with the totals
 *      counted from those rows. The DHT lookup runs behind
 *      node_rpc_client's test hook and the per-blob fetch behind
 *      zcl_native_zcode_discovery_test_backend: no socket, no daemon.
 *   3e. The attestation POINTER publish gate
 *      (engine/composition/src/boot_zcode_dht_publish_gate.c): NO_PACKAGE_STORE,
 *      ATTESTATION_NOT_HELD, ATTESTATION_INVALID,
 *      ATTESTATION_BINDING_MISMATCH (a pointer whose semantic_root is
 *      not the attestation's package_root, refused before anything is
 *      filed) and ATTESTATION_STORE_CONFLICT, each reached by
 *      construction and asserted by its named code plus the exact
 *      transport rule; the happy path passes and files the attestation.
 *   4. End-to-end external verifier: a tiny real C package is published
 *      into a fixture store, build/bin/zclassic23-package-verify runs it
 *      (gcc + clang, plain + ASan/UBSan), and the signed attestation is
 *      checked (test-pass, verifier key, temp tree cleaned). Hostile
 *      fixtures fail closed with the named rule: a syntax-error source
 *      (build-fail/compile-error) and a test that calls socket()
 *      (test-fail/test-signal — the seccomp network denial firing). The
 *      reproduction lane runs --emit twice: a second build
 *      --reproduce-against the first build-report exits 0 with
 *      reproduction=MATCH; a tampered reference exits 6 (MISMATCH).
 *
 * Command handlers run in-process on ./test-tmp datadirs. The e2e lane
 * forks the real verifier binary — it MUST exist (make
 * zclassic23-package-verify); a missing binary is a loud failure, never
 * a silent skip. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_zcode_discovery.h"

#include "base/safe_alloc.h"
#include "config/boot_zcode_dht_publish_gate.h"
#include "controllers/rpc_client.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"
#include "util/spawn.h"
#include "util/util.h"
#include "vcs/blob_store.h"
#include "vcs/package_attest.h"
#include "vcs/package_attest_transport.h"
#include "vcs/package_store.h"
#include "vcs/source_package_checkout.h"
#include "vcs/zcode_dht_record.h"
#include "vcs/zcode_task_context.h"
#include "vcs/package_build.h"
#include "vcs/package_eligible.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"
#include "vcs/package_reproduce.h"
#include "vcs/package_verify_policy.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZV_CHECK(name, expr) do {                                     \
    if (expr) { printf("  zcode_verify: %s... OK\n", (name)); }       \
    else { printf("  zcode_verify: %s... FAIL\n", (name)); failures++; } \
} while (0)

#define ZV_VERIFIER_BIN "build/bin/zclassic23-package-verify-dev"

/* ── small fixtures ─────────────────────────────────────────────────── */

static void zv_hex_enc(const uint8_t *in, size_t len, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[in[i] & 0xf];
    }
    out[2 * len] = '\0';
}

static bool zv_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static bool zv_pubkey_hex(uint8_t seed, char out[67])
{
    struct privkey sk;
    struct pubkey pk;
    if (!zv_keypair(seed, &sk, &pk))
        return false;
    zv_hex_enc(pk.vch, pk.size, out);
    return true;
}

static bool zv_mkdir_p(const char *path)
{
    char buf[4096];
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

static bool zv_rm_rf(const char *path)
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
        char child[4096];
        int n = snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child)) {
            ok = false;
            continue;
        }
        if (!zv_rm_rf(child))
            ok = false;
    }
    closedir(dir);
    if (rmdir(path) != 0)
        ok = false;
    return ok;
}

static bool zv_write_file(const char *path, const void *data, size_t len,
                          mode_t mode)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    size_t written = fwrite(data, 1, len, f);
    if (fclose(f) != 0 || written != len)
        return false;
    return chmod(path, mode) == 0;
}

static bool zv_read_file(const char *path, uint8_t *out, size_t cap,
                         size_t *out_len)
{
    *out_len = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t len = fread(out, 1, cap, f);
    bool ok = !ferror(f) && feof(f) && len > 0;
    fclose(f);
    if (!ok)
        return false;
    *out_len = len;
    return true;
}

/* ── attestation fixtures ───────────────────────────────────────────── */

static bool zv_sign_attest(struct vcs_package_attest *a, struct privkey *sk)
{
    uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
    if (vcs_package_attest_id(a, id) != VCS_PACKAGE_ATTEST_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(sk, &hash, compact))
        return false;
    memcpy(a->signature, compact + 1, VCS_PACKAGE_ATTEST_SIGNATURE_BYTES);
    return true;
}

/* A valid, signed attestation of the given class over the given roots,
 * signed by the given key. Field sets mirror what the external verifier
 * produces (clang + gcc, ASan + UBSan where tests run). */
static bool zv_attest(struct vcs_package_attest *a, uint8_t cls,
                      const uint8_t package_root[32],
                      const uint8_t release_id[32],
                      const uint8_t recipe_root[32],
                      uint8_t signer_seed)
{
    struct privkey sk;
    struct pubkey pk;
    if (!zv_keypair(signer_seed, &sk, &pk))
        return false;
    memset(a, 0, sizeof(*a));
    a->schema_version = VCS_PACKAGE_ATTEST_VERSION;
    memcpy(a->package_root, package_root, 32);
    memcpy(a->release_id, release_id, 32);
    memcpy(a->recipe_root, recipe_root, 32);
    a->result_class = cls;
    snprintf(a->compilers[0].id, sizeof(a->compilers[0].id), "clang");
    snprintf(a->compilers[0].version, sizeof(a->compilers[0].version),
             "18.1.3");
    snprintf(a->compilers[1].id, sizeof(a->compilers[1].id), "gcc");
    snprintf(a->compilers[1].version, sizeof(a->compilers[1].version),
             "13.2.0");
    a->compiler_count = 2;
    a->compilers[0].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
    a->compilers[1].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
    a->isolation = VCS_PACKAGE_ATTEST_ISOLATION_FULL;
    switch (cls) {
    case VCS_PACKAGE_ATTEST_RESULT_BUILD_PASS:
        a->test_ran = false;
        break;
    case VCS_PACKAGE_ATTEST_RESULT_BUILD_FAIL:
        a->test_ran = false;
        a->detail_code = VCS_PACKAGE_ATTEST_DETAIL_COMPILE_ERROR;
        snprintf(a->detail, sizeof(a->detail),
                 "gcc: src/x.c:4:5: error: expected expression");
        a->compilers[0].outcome = VCS_PACKAGE_ATTEST_OUTCOME_FAIL;
        break;
    case VCS_PACKAGE_ATTEST_RESULT_TEST_PASS:
        a->test_ran = true;
        a->test_exit_code = 0;
        snprintf(a->sanitizers[0].name, sizeof(a->sanitizers[0].name),
                 "asan");
        snprintf(a->sanitizers[1].name, sizeof(a->sanitizers[1].name),
                 "ubsan");
        a->sanitizer_count = 2;
        a->sanitizers[0].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
        a->sanitizers[1].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
        break;
    case VCS_PACKAGE_ATTEST_RESULT_TEST_FAIL:
        a->test_ran = true;
        a->test_exit_code = 1;
        a->detail_code = VCS_PACKAGE_ATTEST_DETAIL_TEST_EXIT_MISMATCH;
        snprintf(a->detail, sizeof(a->detail), "gcc: exit 1, expected 0");
        snprintf(a->sanitizers[0].name, sizeof(a->sanitizers[0].name),
                 "asan");
        snprintf(a->sanitizers[1].name, sizeof(a->sanitizers[1].name),
                 "ubsan");
        a->sanitizer_count = 2;
        a->sanitizers[0].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
        a->sanitizers[1].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
        break;
    case VCS_PACKAGE_ATTEST_RESULT_SANITIZER_FAIL:
        a->test_ran = true;
        a->test_exit_code = 99;
        a->detail_code = VCS_PACKAGE_ATTEST_DETAIL_ASAN_FINDINGS;
        snprintf(a->detail, sizeof(a->detail),
                 "gcc+san: exit 99, expected 0");
        snprintf(a->sanitizers[0].name, sizeof(a->sanitizers[0].name),
                 "asan");
        snprintf(a->sanitizers[1].name, sizeof(a->sanitizers[1].name),
                 "ubsan");
        a->sanitizer_count = 2;
        a->sanitizers[0].outcome = VCS_PACKAGE_ATTEST_OUTCOME_FAIL;
        a->sanitizers[1].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
        break;
    default:
        return false;
    }
    memcpy(a->verifier_pubkey, pk.vch, 33);
    return zv_sign_attest(a, &sk);
}

static void zv_pattern_root(uint8_t seed, uint8_t out[32])
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(seed + i);
}

/* ── 1. codec ───────────────────────────────────────────────────────── */

static int t_codec(void)
{
    int failures = 0;
    uint8_t pr[32], ri[32], rr[32];
    zv_pattern_root(0x10, pr);
    zv_pattern_root(0x40, ri);
    zv_pattern_root(0x80, rr);

    /* Roundtrip for every result class. */
    static const uint8_t k_classes[] = {
        VCS_PACKAGE_ATTEST_RESULT_BUILD_PASS,
        VCS_PACKAGE_ATTEST_RESULT_BUILD_FAIL,
        VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
        VCS_PACKAGE_ATTEST_RESULT_TEST_FAIL,
        VCS_PACKAGE_ATTEST_RESULT_SANITIZER_FAIL,
    };
    bool roundtrip = true;
    for (size_t i = 0; i < sizeof(k_classes); i++) {
        struct vcs_package_attest a;
        if (!zv_attest(&a, k_classes[i], pr, ri, rr, 0x42)) {
            roundtrip = false;
            break;
        }
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        if (vcs_package_attest_serialize(&a, &wire, &wire_len) !=
            VCS_PACKAGE_ATTEST_OK) {
            roundtrip = false;
            break;
        }
        struct vcs_package_attest b;
        bool ok = vcs_package_attest_parse(wire, wire_len, &b) ==
                      VCS_PACKAGE_ATTEST_OK &&
                  vcs_package_attest_verify(&b) == VCS_PACKAGE_ATTEST_OK &&
                  b.result_class == a.result_class &&
                  b.detail_code == a.detail_code &&
                  strcmp(b.detail, a.detail) == 0 &&
                  b.compiler_count == a.compiler_count &&
                  b.sanitizer_count == a.sanitizer_count &&
                  b.test_ran == a.test_ran &&
                  b.test_exit_code == a.test_exit_code &&
                  b.isolation == a.isolation &&
                  memcmp(b.verifier_pubkey, a.verifier_pubkey, 33) == 0 &&
                  memcmp(b.signature, a.signature, 64) == 0;
        free(wire);
        if (!ok) {
            roundtrip = false;
            break;
        }
    }
    ZV_CHECK("codec: roundtrip every result class", roundtrip);

    /* KAT: the frozen attestation id guards the canonical encoding. */
    struct vcs_package_attest kat;
    bool kat_ok = zv_attest(&kat, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pr,
                            ri, rr, 0x42);
    uint8_t kat_id[32];
    char kat_hex[65];
    if (kat_ok)
        kat_ok = vcs_package_attest_id(&kat, kat_id) ==
                 VCS_PACKAGE_ATTEST_OK;
    if (kat_ok)
        zv_hex_enc(kat_id, 32, kat_hex);
    static const char *k_kat_expect =
        "b67be9be495ffd9f381fd729273c40609e3e92d77233c530fdd8ce018d57da20";
    ZV_CHECK("codec: frozen KAT attestation id",
             kat_ok && strcmp(kat_hex, k_kat_expect) == 0);
    if (kat_ok && strcmp(kat_hex, k_kat_expect) != 0)
        printf("  zcode_verify: KAT actual %s\n", kat_hex);

    /* Hostile wires. */
    struct vcs_package_attest a;
    if (!zv_attest(&a, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pr, ri, rr,
                   0x42)) {
        ZV_CHECK("codec: fixture builds", false);
        return failures + 1;
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_attest_serialize(&a, &wire, &wire_len) !=
            VCS_PACKAGE_ATTEST_OK) {
        ZV_CHECK("codec: fixture serializes", false);
        return failures + 1;
    }
    struct vcs_package_attest out;
    ZV_CHECK("codec: truncated wire",
             vcs_package_attest_parse(wire, wire_len - 10, &out) ==
                 VCS_PACKAGE_ATTEST_ERR_WIRE_TRUNCATED);
    {
        uint8_t bigger[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES + 1u];
        memcpy(bigger, wire, wire_len);
        bigger[wire_len] = 0x00;
        ZV_CHECK("codec: trailing byte",
                 vcs_package_attest_parse(bigger, wire_len + 1, &out) ==
                     VCS_PACKAGE_ATTEST_ERR_WIRE_TRAILING);
        ZV_CHECK("codec: oversize wire",
                 vcs_package_attest_parse(bigger, sizeof(bigger), &out) ==
                     VCS_PACKAGE_ATTEST_ERR_WIRE_OVERSIZE);
    }
    {
        uint8_t bad[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
        memcpy(bad, wire, wire_len);
        bad[0] ^= 0x01;
        ZV_CHECK("codec: bad magic",
                 vcs_package_attest_parse(bad, wire_len, &out) ==
                     VCS_PACKAGE_ATTEST_ERR_WIRE_MAGIC);
        memcpy(bad, wire, wire_len);
        bad[8] = 2; /* schema_version low byte */
        bad[9] = 0;
        ZV_CHECK("codec: unknown version",
                 vcs_package_attest_parse(bad, wire_len, &out) ==
                     VCS_PACKAGE_ATTEST_ERR_SCHEMA_VERSION);
        memcpy(bad, wire, wire_len);
        bad[106] = 9; /* result class */
        ZV_CHECK("codec: unknown result class",
                 vcs_package_attest_parse(bad, wire_len, &out) ==
                     VCS_PACKAGE_ATTEST_ERR_RESULT_CLASS);
        memcpy(bad, wire, wire_len);
        bad[107] = 250; /* detail code */
        ZV_CHECK("codec: unknown detail code",
                 vcs_package_attest_parse(bad, wire_len, &out) ==
                     VCS_PACKAGE_ATTEST_ERR_DETAIL_CODE);
    }
    free(wire);

    /* Consistency rules via validate() on mutated structs. */
    struct vcs_package_attest m;
    ZV_CHECK("codec: validate accepts the fixture",
             zv_attest(&m, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pr, ri, rr,
                       0x42) &&
             vcs_package_attest_validate(&m) == VCS_PACKAGE_ATTEST_OK);
    zv_attest(&m, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pr, ri, rr, 0x42);
    memset(m.package_root, 0, 32);
    ZV_CHECK("codec: zero package root",
             vcs_package_attest_validate(&m) ==
                 VCS_PACKAGE_ATTEST_ERR_PACKAGE_ROOT);
    zv_attest(&m, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pr, ri, rr, 0x42);
    m.detail[0] = 0x01;
    ZV_CHECK("codec: non-printable detail",
             vcs_package_attest_validate(&m) ==
                 VCS_PACKAGE_ATTEST_ERR_DETAIL_TEXT);
    zv_attest(&m, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pr, ri, rr, 0x42);
    snprintf(m.detail, sizeof(m.detail), "surplus");
    ZV_CHECK("codec: pass class carrying detail",
             vcs_package_attest_validate(&m) ==
                 VCS_PACKAGE_ATTEST_ERR_DETAIL_FORBIDDEN);
    zv_attest(&m, VCS_PACKAGE_ATTEST_RESULT_TEST_FAIL, pr, ri, rr, 0x42);
    m.detail_code = VCS_PACKAGE_ATTEST_DETAIL_NONE;
    ZV_CHECK("codec: fail class without detail code",
             vcs_package_attest_validate(&m) ==
                 VCS_PACKAGE_ATTEST_ERR_DETAIL_REQUIRED);
    zv_attest(&m, VCS_PACKAGE_ATTEST_RESULT_BUILD_PASS, pr, ri, rr, 0x42);
    m.test_ran = true;
    ZV_CHECK("codec: build-pass with test_ran",
             vcs_package_attest_validate(&m) ==
                 VCS_PACKAGE_ATTEST_ERR_TEST_CLASS);
    zv_attest(&m, VCS_PACKAGE_ATTEST_RESULT_BUILD_PASS, pr, ri, rr, 0x42);
    m.test_exit_code = 3;
    ZV_CHECK("codec: non-canonical exit code without a test run",
             vcs_package_attest_validate(&m) ==
                 VCS_PACKAGE_ATTEST_ERR_TEST_EXIT);
    zv_attest(&m, VCS_PACKAGE_ATTEST_RESULT_SANITIZER_FAIL, pr, ri, rr,
              0x42);
    m.sanitizers[0].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
    ZV_CHECK("codec: sanitizer-fail without findings",
             vcs_package_attest_validate(&m) ==
                 VCS_PACKAGE_ATTEST_ERR_SANITIZER_FINDINGS);
    zv_attest(&m, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pr, ri, rr, 0x42);
    m.sanitizers[1].outcome = VCS_PACKAGE_ATTEST_OUTCOME_FAIL;
    ZV_CHECK("codec: findings in a pass class",
             vcs_package_attest_validate(&m) ==
                 VCS_PACKAGE_ATTEST_ERR_SANITIZER_FINDINGS);
    zv_attest(&m, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pr, ri, rr, 0x42);
    m.compilers[1].outcome = VCS_PACKAGE_ATTEST_OUTCOME_FAIL;
    ZV_CHECK("codec: failed compiler in a pass class",
             vcs_package_attest_validate(&m) ==
                 VCS_PACKAGE_ATTEST_ERR_OUTCOME_CLASS);
    zv_attest(&m, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pr, ri, rr, 0x42);
    {
        struct vcs_package_attest_compiler tmp = m.compilers[0];
        m.compilers[0] = m.compilers[1];
        m.compilers[1] = tmp;
    }
    ZV_CHECK("codec: unsorted compilers",
             vcs_package_attest_validate(&m) ==
                 VCS_PACKAGE_ATTEST_ERR_COMPILER_ORDER);
    zv_attest(&m, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pr, ri, rr, 0x42);
    m.isolation = 9;
    ZV_CHECK("codec: unknown isolation level",
             vcs_package_attest_validate(&m) ==
                 VCS_PACKAGE_ATTEST_ERR_ISOLATION);
    return failures;
}

static int t_signature(void)
{
    int failures = 0;
    uint8_t pr[32], ri[32], rr[32];
    zv_pattern_root(0x10, pr);
    zv_pattern_root(0x40, ri);
    zv_pattern_root(0x80, rr);
    struct vcs_package_attest a;
    bool ok = zv_attest(&a, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pr, ri,
                        rr, 0x42);
    ZV_CHECK("sign: signed attestation verifies",
             ok && vcs_package_attest_verify(&a) == VCS_PACKAGE_ATTEST_OK);
    struct vcs_package_attest m = a;
    m.signature[7] ^= 0x01;
    ZV_CHECK("sign: flipped signature byte",
             vcs_package_attest_verify(&m) ==
                 VCS_PACKAGE_ATTEST_ERR_SIG_VERIFY);
    m = a;
    memset(m.signature + 32, 0xff, 32); /* s = 2^256-1 > n/2 */
    ZV_CHECK("sign: high-S malleation",
             vcs_package_attest_verify(&m) ==
                 VCS_PACKAGE_ATTEST_ERR_SIG_LOW_S);
    m = a;
    {
        struct pubkey other;
        struct privkey osk;
        zv_keypair(0x99, &osk, &other);
        memcpy(m.verifier_pubkey, other.vch, 33);
    }
    ZV_CHECK("sign: wrong verifier key",
             vcs_package_attest_verify(&m) ==
                 VCS_PACKAGE_ATTEST_ERR_SIG_VERIFY);
    m = a;
    m.test_exit_code ^= 1; /* tamper after signing */
    ZV_CHECK("sign: tampered field",
             vcs_package_attest_verify(&m) ==
                 VCS_PACKAGE_ATTEST_ERR_SIG_VERIFY);
    return failures;
}

/* ── 2. policy + quorum ─────────────────────────────────────────────── */

static int t_policy(void)
{
    int failures = 0;
    char ka[67], kb[67];
    zv_pubkey_hex(0x22, ka);
    zv_pubkey_hex(0x33, kb);

    struct vcs_verifier_policy p;
    vcs_verifier_policy_init(&p);
    char text[256];
    snprintf(text, sizeof(text), "# approved verifiers\n\n%s\n%s\n", ka,
             kb);
    enum vcs_verifier_policy_error err = VCS_VERIFIER_POLICY_OK;
    ZV_CHECK("policy: comments and blanks parse",
             vcs_verifier_policy_parse_text(&p, text, strlen(text), &err,
                                            NULL) &&
             p.count == 2);

    vcs_verifier_policy_init(&p);
    size_t line = 0;
    ZV_CHECK("policy: malformed line names the rule and line",
             !vcs_verifier_policy_parse_text(&p, "zz\n", 3, &err, &line) &&
             err == VCS_VERIFIER_POLICY_ERR_KEY_GRAMMAR && line == 1);

    vcs_verifier_policy_init(&p);
    snprintf(text, sizeof(text), "%s\n%s\n", ka, ka);
    ZV_CHECK("policy: duplicate key rejected at its line",
             !vcs_verifier_policy_parse_text(&p, text, strlen(text), &err,
                                             &line) &&
             err == VCS_VERIFIER_POLICY_ERR_DUPLICATE && line == 2);

    vcs_verifier_policy_init(&p);
    {
        char offcurve[67];
        snprintf(offcurve, sizeof(offcurve),
                 "0200000000000000000000000000000000000000000000000000000000"
                 "00000000");
        ZV_CHECK("policy: off-curve key rejected",
                 !vcs_verifier_policy_parse_text(&p, offcurve,
                                                 strlen(offcurve), &err,
                                                 NULL) &&
                 err == VCS_VERIFIER_POLICY_ERR_KEY_OFFCURVE);
    }

    /* The 64-key bound. */
    vcs_verifier_policy_init(&p);
    bool bound_ok = true;
    for (size_t i = 0; i < VCS_VERIFIER_POLICY_MAX_KEYS; i++) {
        uint8_t key[33];
        struct privkey sk;
        struct pubkey pk;
        if (!zv_keypair((uint8_t)(0x30 + i), &sk, &pk)) {
            bound_ok = false;
            break;
        }
        memcpy(key, pk.vch, 33);
        if (!vcs_verifier_policy_add(&p, key, &err)) {
            bound_ok = false;
            break;
        }
    }
    if (bound_ok) {
        uint8_t extra[33];
        struct privkey sk;
        struct pubkey pk;
        zv_keypair(0x01, &sk, &pk);
        memcpy(extra, pk.vch, 33);
        bound_ok = !vcs_verifier_policy_add(&p, extra, &err) &&
                   err == VCS_VERIFIER_POLICY_ERR_TOO_MANY;
    }
    ZV_CHECK("policy: 64-key bound", bound_ok);
    return failures;
}

struct zv_quorum_ctx {
    uint8_t package_root[32];
    uint8_t release_id[32];
    uint8_t recipe_root[32];
    uint8_t publisher[33];
    struct vcs_verifier_policy policy;
};

static void zv_quorum_ctx_init(struct zv_quorum_ctx *ctx)
{
    zv_pattern_root(0x10, ctx->package_root);
    zv_pattern_root(0x40, ctx->release_id);
    zv_pattern_root(0x80, ctx->recipe_root);
    struct privkey sk;
    struct pubkey pk;
    zv_keypair(0x11, &sk, &pk);
    memcpy(ctx->publisher, pk.vch, 33);
    vcs_verifier_policy_init(&ctx->policy);
    for (uint8_t seed = 0x22; seed <= 0x25; seed++) {
        zv_keypair(seed, &sk, &pk);
        vcs_verifier_policy_add(&ctx->policy, pk.vch, NULL);
    }
}

static bool zv_row_rule_is(const struct vcs_verify_quorum *q, size_t i,
                           enum vcs_verify_row_rule rule)
{
    return i < q->row_count && q->rows[i].rule == rule;
}

static int t_quorum(void)
{
    int failures = 0;
    struct zv_quorum_ctx ctx;
    zv_quorum_ctx_init(&ctx);

    /* 2-of-N approved matching -> verified. */
    {
        struct vcs_verify_candidate cands[2];
        cands[0].parsed = zv_attest(&cands[0].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                    ctx.package_root, ctx.release_id,
                                    ctx.recipe_root, 0x22);
        cands[1].parsed = zv_attest(&cands[1].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                    ctx.package_root, ctx.release_id,
                                    ctx.recipe_root, 0x23);
        struct vcs_verify_quorum q;
        vcs_verify_evaluate(cands, 2, ctx.package_root, ctx.recipe_root,
                            ctx.publisher, &ctx.policy, &q);
        ZV_CHECK("quorum: two approved matching verify",
                 cands[0].parsed && cands[1].parsed && q.verified &&
                 q.quorum_reached && q.quorum_signers == 2 &&
                 q.quorum_class == VCS_PACKAGE_ATTEST_RESULT_TEST_PASS &&
                 zv_row_rule_is(&q, 0, VCS_VERIFY_ROW_COUNTED) &&
                 zv_row_rule_is(&q, 1, VCS_VERIFY_ROW_COUNTED));
    }

    /* Three matching signers count three. */
    {
        struct vcs_verify_candidate cands[3];
        for (size_t i = 0; i < 3; i++)
            cands[i].parsed = zv_attest(
                &cands[i].attestation, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                ctx.package_root, ctx.release_id, ctx.recipe_root,
                (uint8_t)(0x22 + i));
        struct vcs_verify_quorum q;
        vcs_verify_evaluate(cands, 3, ctx.package_root, ctx.recipe_root,
                            ctx.publisher, &ctx.policy, &q);
        ZV_CHECK("quorum: 3-of-N counts three signers",
                 q.verified && q.quorum_signers == 3);
    }

    /* Non-matching classes never reach a quorum. */
    {
        struct vcs_verify_candidate cands[2];
        cands[0].parsed = zv_attest(&cands[0].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                    ctx.package_root, ctx.release_id,
                                    ctx.recipe_root, 0x22);
        cands[1].parsed = zv_attest(&cands[1].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_TEST_FAIL,
                                    ctx.package_root, ctx.release_id,
                                    ctx.recipe_root, 0x23);
        struct vcs_verify_quorum q;
        vcs_verify_evaluate(cands, 2, ctx.package_root, ctx.recipe_root,
                            ctx.publisher, &ctx.policy, &q);
        ZV_CHECK("quorum: different result classes do not verify",
                 !q.verified && !q.quorum_reached &&
                 q.counted == 2);
    }

    /* An unapproved key is named and never counted. */
    {
        struct vcs_verify_candidate cands[2];
        cands[0].parsed = zv_attest(&cands[0].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                    ctx.package_root, ctx.release_id,
                                    ctx.recipe_root, 0x22);
        cands[1].parsed = zv_attest(&cands[1].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                    ctx.package_root, ctx.release_id,
                                    ctx.recipe_root, 0x44); /* not listed */
        struct vcs_verify_quorum q;
        vcs_verify_evaluate(cands, 2, ctx.package_root, ctx.recipe_root,
                            ctx.publisher, &ctx.policy, &q);
        ZV_CHECK("quorum: unapproved signer named, no quorum",
                 !q.verified && q.counted == 1 &&
                 zv_row_rule_is(&q, 1, VCS_VERIFY_ROW_SIGNER_NOT_APPROVED));
    }

    /* Self-verification (publisher == verifier) is rejected even when the
     * operator foolishly approved the publisher key. */
    {
        struct vcs_verifier_policy with_self;
        vcs_verifier_policy_init(&with_self);
        vcs_verifier_policy_add(&with_self, ctx.publisher, NULL);
        struct privkey sk;
        struct pubkey pk;
        zv_keypair(0x22, &sk, &pk);
        vcs_verifier_policy_add(&with_self, pk.vch, NULL);
        struct vcs_verify_candidate cands[2];
        cands[0].parsed = zv_attest(&cands[0].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                    ctx.package_root, ctx.release_id,
                                    ctx.recipe_root, 0x11); /* publisher */
        cands[1].parsed = zv_attest(&cands[1].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                    ctx.package_root, ctx.release_id,
                                    ctx.recipe_root, 0x22);
        struct vcs_verify_quorum q;
        vcs_verify_evaluate(cands, 2, ctx.package_root, ctx.recipe_root,
                            ctx.publisher, &with_self, &q);
        ZV_CHECK("quorum: self-verification rejected",
                 !q.verified && q.counted == 1 &&
                 zv_row_rule_is(&q, 0, VCS_VERIFY_ROW_SELF_VERIFICATION));
    }

    /* A duplicate signer counts once (second attestation differs in the
     * compiler versions — it still MATCHES on roots+class). */
    {
        struct vcs_verify_candidate cands[2];
        cands[0].parsed = zv_attest(&cands[0].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                    ctx.package_root, ctx.release_id,
                                    ctx.recipe_root, 0x22);
        cands[1].parsed = zv_attest(&cands[1].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                    ctx.package_root, ctx.release_id,
                                    ctx.recipe_root, 0x22);
        if (cands[1].parsed)
            snprintf(cands[1].attestation.compilers[1].version,
                     sizeof(cands[1].attestation.compilers[1].version),
                     "14.1.0");
        /* Re-sign after the field change. */
        struct privkey sk;
        struct pubkey pk;
        zv_keypair(0x22, &sk, &pk);
        cands[1].parsed = cands[1].parsed &&
                          zv_sign_attest(&cands[1].attestation, &sk);
        struct vcs_verify_quorum q;
        vcs_verify_evaluate(cands, 2, ctx.package_root, ctx.recipe_root,
                            ctx.publisher, &ctx.policy, &q);
        ZV_CHECK("quorum: duplicate signer counts once",
                 !q.verified && q.counted == 1 &&
                 zv_row_rule_is(&q, 1, VCS_VERIFY_ROW_DUPLICATE_SIGNER));
    }

    /* A quorum on a FAIL class is reached but never "verified". */
    {
        struct vcs_verify_candidate cands[2];
        cands[0].parsed = zv_attest(&cands[0].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_BUILD_FAIL,
                                    ctx.package_root, ctx.release_id,
                                    ctx.recipe_root, 0x22);
        cands[1].parsed = zv_attest(&cands[1].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_BUILD_FAIL,
                                    ctx.package_root, ctx.release_id,
                                    ctx.recipe_root, 0x23);
        struct vcs_verify_quorum q;
        vcs_verify_evaluate(cands, 2, ctx.package_root, ctx.recipe_root,
                            ctx.publisher, &ctx.policy, &q);
        ZV_CHECK("quorum: fail-class quorum is not verified",
                 !q.verified && q.quorum_reached && q.quorum_signers == 2 &&
                 q.quorum_class == VCS_PACKAGE_ATTEST_RESULT_BUILD_FAIL);
    }

    /* A different recipe root is a named mismatch, never a match. */
    {
        uint8_t other_recipe[32];
        zv_pattern_root(0x90, other_recipe);
        struct vcs_verify_candidate cands[2];
        cands[0].parsed = zv_attest(&cands[0].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                    ctx.package_root, ctx.release_id,
                                    ctx.recipe_root, 0x22);
        cands[1].parsed = zv_attest(&cands[1].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                    ctx.package_root, ctx.release_id,
                                    other_recipe, 0x33);
        struct vcs_verify_quorum q;
        vcs_verify_evaluate(cands, 2, ctx.package_root, ctx.recipe_root,
                            ctx.publisher, &ctx.policy, &q);
        ZV_CHECK("quorum: recipe mismatch named, no quorum",
                 !q.verified && q.counted == 1 &&
                 zv_row_rule_is(&q, 1, VCS_VERIFY_ROW_RECIPE_ROOT_MISMATCH));
    }

    /* An invalid signature and an unparseable wire are named invalid. */
    {
        struct vcs_verify_candidate cands[3];
        cands[0].parsed = zv_attest(&cands[0].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                    ctx.package_root, ctx.release_id,
                                    ctx.recipe_root, 0x22);
        cands[1].parsed = zv_attest(&cands[1].attestation,
                                    VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                    ctx.package_root, ctx.release_id,
                                    ctx.recipe_root, 0x33);
        if (cands[1].parsed)
            cands[1].attestation.signature[0] ^= 0x01;
        cands[2].parsed = false;
        struct vcs_verify_quorum q;
        vcs_verify_evaluate(cands, 3, ctx.package_root, ctx.recipe_root,
                            ctx.publisher, &ctx.policy, &q);
        ZV_CHECK("quorum: invalid attestations named",
                 !q.verified && q.counted == 1 &&
                 zv_row_rule_is(&q, 1, VCS_VERIFY_ROW_ATTESTATION_INVALID) &&
                 zv_row_rule_is(&q, 2, VCS_VERIFY_ROW_ATTESTATION_INVALID) &&
                 !q.rows[2].has_pubkey);
    }
    return failures;
}

/* ── 3. zcode package verify command ────────────────────────────────── */

struct zv_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void zv_cmd_init(struct zv_cmd *c, const char *datadir,
                        const char *root_hex)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.zcode_verify_test.v1");
    (void)json_push_kv_str(&c->input, "datadir", datadir);
    (void)json_push_kv_str(&c->input, "root", root_hex);
}

static void zv_cmd_free(struct zv_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* Publish one tiny fixture package into <store>: manifest + chunks +
 * recipe + a signed release by publisher key 0x11. Fills the roots.
 * `program_content` (nullable) adds `app/main.c` as a recipe PROGRAM, which
 * raises the recipe to schema 2 and makes the verifier link and emit
 * bin/<package short name>; NULL keeps the historical library-only,
 * schema-1 fixture byte-for-byte. */
static bool zv_publish_fixture_ex(const char *store, const char *src_content,
                                  const char *test_content,
                                  const char *program_content,
                                  uint8_t package_root_out[32],
                                  uint8_t release_id_out[32],
                                  uint8_t recipe_root_out[32])
{
    char dir[4400];
    snprintf(dir, sizeof(dir), "%s/manifests", store);
    if (!zv_mkdir_p(dir))
        return false;
    snprintf(dir, sizeof(dir), "%s/releases", store);
    if (!zv_mkdir_p(dir))
        return false;
    snprintf(dir, sizeof(dir), "%s/recipes", store);
    if (!zv_mkdir_p(dir))
        return false;
    snprintf(dir, sizeof(dir), "%s/attestations", store);
    if (!zv_mkdir_p(dir))
        return false;
    snprintf(dir, sizeof(dir), "%s/cas/sha3", store);
    if (!zv_mkdir_p(dir))
        return false;

    struct {
        const char *path;
        const char *content;
    } files[] = {
        { "src/add.h", "#pragma once\nint add(int a, int b);\n" },
        { "src/add.c", src_content },
        { "test/test_add.c", test_content },
        { "app/main.c", program_content },
    };
    const size_t file_count = program_content ? 4u : 3u;
    struct vcs_package_manifest m;
    vcs_package_manifest_init(&m);
    bool ok = true;
    for (size_t i = 0; i < file_count && ok; i++) {
        size_t len = strlen(files[i].content);
        uint8_t hash[32];
        struct sha3_256_ctx c;
        sha3_256_init(&c);
        sha3_256_write(&c, (const uint8_t *)files[i].content, len);
        sha3_256_finalize(&c, hash);
        ok = vcs_package_manifest_add(&m, files[i].path,
                                      VCS_PACKAGE_MODE_FILE, len, hash, 1);
        if (ok) {
            char hex[65];
            zv_hex_enc(hash, 32, hex);
            char chunk_dir[4400];
            snprintf(chunk_dir, sizeof(chunk_dir), "%s/cas/sha3/%.2s",
                     store, hex);
            char chunk_path[4400];
            snprintf(chunk_path, sizeof(chunk_path), "%s/%s", chunk_dir,
                     hex);
            ok = zv_mkdir_p(chunk_dir) &&
                 zv_write_file(chunk_path, files[i].content, len, 0600);
        }
    }
    if (ok)
        ok = vcs_package_manifest_root(&m, package_root_out);
    uint8_t *mwire = NULL;
    size_t mwire_len = 0;
    if (ok)
        ok = vcs_package_manifest_serialize(&m, &mwire, &mwire_len);
    vcs_package_manifest_free(&m);
    if (!ok)
        return false;
    char root_hex[65];
    zv_hex_enc(package_root_out, 32, root_hex);
    char path[4400];
    snprintf(path, sizeof(path), "%s/manifests/%s", store, root_hex);
    ok = zv_write_file(path, mwire, mwire_len, 0600);
    free(mwire);
    if (!ok)
        return false;

    struct vcs_package_recipe r;
    vcs_package_recipe_init(&r);
    ok = vcs_package_recipe_add_header(&r, "src/add.h", NULL) &&
         vcs_package_recipe_add_source(&r, "src/add.c", NULL) &&
         vcs_package_recipe_add_test_source(&r, "test/test_add.c", NULL) &&
         vcs_package_recipe_add_include_dir(&r, "src", NULL) &&
         vcs_package_recipe_add_library(&r, VCS_PACKAGE_RECIPE_LIB_LIBC,
                                        NULL) &&
         (!program_content ||
          vcs_package_recipe_add_program(&r, "app/main.c", NULL));
    vcs_package_recipe_set_test_limits(&r, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    uint8_t *rwire = NULL;
    size_t rwire_len = 0;
    if (ok)
        ok = vcs_package_recipe_root(&r, recipe_root_out) ==
                 VCS_PACKAGE_RECIPE_OK &&
             vcs_package_recipe_serialize(&r, &rwire, &rwire_len) ==
                 VCS_PACKAGE_RECIPE_OK;
    vcs_package_recipe_free(&r);
    if (!ok)
        return false;
    char rroot_hex[65];
    zv_hex_enc(recipe_root_out, 32, rroot_hex);
    snprintf(path, sizeof(path), "%s/recipes/%s", store, rroot_hex);
    ok = zv_write_file(path, rwire, rwire_len, 0600);
    free(rwire);
    if (!ok)
        return false;

    struct privkey sk;
    struct pubkey pk;
    if (!zv_keypair(0x11, &sk, &pk))
        return false;
    struct vcs_package_release rel;
    memset(&rel, 0, sizeof(rel));
    rel.schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(rel.name, sizeof(rel.name), "alice/addpkg");
    snprintf(rel.semver, sizeof(rel.semver), "1.0.0");
    memcpy(rel.package_root, package_root_out, 32);
    rel.has_parent = false;
    memcpy(rel.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    rel.publisher_sequence = 1;
    snprintf(rel.reward_address, sizeof(rel.reward_address), "t1fixture");
    snprintf(rel.license, sizeof(rel.license), "MIT");
    memcpy(rel.recipe_root, recipe_root_out, 32);
    rel.has_znam = false;
    snprintf(rel.chain_id, sizeof(rel.chain_id), "zclassic-main");
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(&rel, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&sk, &hash, compact))
        return false;
    memcpy(rel.signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    uint8_t *relwire = NULL;
    size_t relwire_len = 0;
    if (vcs_package_release_serialize(&rel, &relwire, &relwire_len) !=
        VCS_PACKAGE_RELEASE_OK)
        return false;
    memcpy(release_id_out, id, 32);
    char id_hex[65];
    zv_hex_enc(id, 32, id_hex);
    snprintf(path, sizeof(path), "%s/releases/%s", store, id_hex);
    ok = zv_write_file(path, relwire, relwire_len, 0600);
    free(relwire);
    return ok;
}

/* The historical library-only fixture: no program, recipe schema 1. */
static bool zv_publish_fixture(const char *store, const char *src_content,
                               const char *test_content,
                               uint8_t package_root_out[32],
                               uint8_t release_id_out[32],
                               uint8_t recipe_root_out[32])
{
    return zv_publish_fixture_ex(store, src_content, test_content, NULL,
                                 package_root_out, release_id_out,
                                 recipe_root_out);
}

/* Persist one signed attestation into <store>/attestations. */
static bool zv_store_attestation(const char *store, uint8_t cls,
                                 const uint8_t package_root[32],
                                 const uint8_t release_id[32],
                                 const uint8_t recipe_root[32],
                                 uint8_t signer_seed)
{
    struct vcs_package_attest a;
    if (!zv_attest(&a, cls, package_root, release_id, recipe_root,
                   signer_seed))
        return false;
    uint8_t id[32];
    if (vcs_package_attest_id(&a, id) != VCS_PACKAGE_ATTEST_OK)
        return false;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_attest_serialize(&a, &wire, &wire_len) !=
        VCS_PACKAGE_ATTEST_OK)
        return false;
    char id_hex[65];
    zv_hex_enc(id, 32, id_hex);
    char path[4400];
    snprintf(path, sizeof(path), "%s/attestations/%s", store, id_hex);
    bool ok = zv_write_file(path, wire, wire_len, 0600);
    free(wire);
    return ok;
}

static bool zv_write_policy(const char *store)
{
    char ka[67], kb[67];
    if (!zv_pubkey_hex(0x22, ka) || !zv_pubkey_hex(0x33, kb))
        return false;
    char text[256];
    int n = snprintf(text, sizeof(text),
                     "# local approved verifiers\n%s\n%s\n", ka, kb);
    char path[4400];
    snprintf(path, sizeof(path), "%s/approved_verifiers", store);
    return n > 0 && zv_write_file(path, text, (size_t)n, 0600);
}

/* ── 3b. bit-identical reproduction fixtures ────────────────────────── */

/* One installable build receipt: two committed outputs seeded by
 * out_seed, under a fixed lock root. compiler_version varies the receipt
 * id (a distinct build event) without touching the output set. */
static bool zv_receipt(struct vcs_package_build_receipt *r,
                       const uint8_t package_root[32],
                       const uint8_t recipe_root[32],
                       const char *compiler_version, uint8_t out_seed)
{
    vcs_package_build_receipt_init(r);
    memcpy(r->package_root, package_root, 32);
    memcpy(r->recipe_root, recipe_root, 32);
    zv_pattern_root(0x77, r->lock_root);
    snprintf(r->compiler_id, sizeof(r->compiler_id), "gcc");
    snprintf(r->compiler_version, sizeof(r->compiler_version), "%s",
             compiler_version);
    snprintf(r->flags, sizeof(r->flags), "-std=c23 -O1");
    r->result_class = (uint8_t)VCS_PACKAGE_BUILD_RESULT_TEST_PASS;
    r->isolation = (uint8_t)VCS_PACKAGE_BUILD_ISOLATION_FULL;
    r->test_ran = true;
    r->test_exit_code = 0;
    uint8_t h1[32], h2[32];
    zv_pattern_root(out_seed, h1);
    zv_pattern_root((uint8_t)(out_seed + 1u), h2);
    return vcs_package_build_add_output(r, "include/add.h", h1, 100) ==
               VCS_PACKAGE_BUILD_OK &&
           vcs_package_build_add_output(r, "lib/libaddpkg.a", h2, 4096) ==
               VCS_PACKAGE_BUILD_OK;
}

/* Persist one receipt under <receipts_dir>/<receipt-id-hex> (the install
 * lifecycle's filing convention). */
static bool zv_store_receipt(const char *receipts_dir,
                             const struct vcs_package_build_receipt *r)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_build_serialize(r, &wire, &wire_len) !=
        VCS_PACKAGE_BUILD_OK)
        return false;
    uint8_t id[32];
    bool ok = vcs_package_build_id(r, id) == VCS_PACKAGE_BUILD_OK;
    if (ok) {
        char id_hex[65];
        zv_hex_enc(id, 32, id_hex);
        char path[4400];
        int n = snprintf(path, sizeof(path), "%s/%s", receipts_dir, id_hex);
        ok = n > 0 && (size_t)n < sizeof(path) &&
             zv_mkdir_p(receipts_dir) &&
             zv_write_file(path, wire, wire_len, 0600);
    }
    free(wire);
    return ok;
}

static int t_build_receipt_v2(void)
{
    int failures = 0;
    uint8_t package_root[32], recipe_root[32], capsule_root[32];
    zv_pattern_root(0x50, package_root);
    zv_pattern_root(0x51, recipe_root);
    zv_pattern_root(0x52, capsule_root);

    /* A receipt init defaults to schema v1 with no capsule; binding a
     * capsule root bumps it to v2. */
    struct vcs_package_build_receipt r;
    ZV_CHECK("receipt v2: fixture builds",
             zv_receipt(&r, package_root, recipe_root, "14.2.0", 0x40));
    ZV_CHECK("receipt v2: init is v1, no capsule",
             r.schema_version == VCS_PACKAGE_BUILD_VERSION_MIN &&
             !r.has_toolchain_capsule);
    ZV_CHECK("receipt v2: zero capsule root rejected",
             vcs_package_build_set_toolchain_capsule(
                 &r, (const uint8_t[32]){ 0 }) == VCS_PACKAGE_BUILD_ERR_CAPSULE &&
             !r.has_toolchain_capsule);
    ZV_CHECK("receipt v2: capsule bind bumps schema",
             vcs_package_build_set_toolchain_capsule(&r, capsule_root) ==
                 VCS_PACKAGE_BUILD_OK &&
             r.schema_version == VCS_PACKAGE_BUILD_VERSION &&
             r.has_toolchain_capsule);

    /* Round-trip: v2 wire preserves the capsule and is exactly 32 bytes
     * longer than the same receipt's v1 wire. */
    uint8_t *wire2 = NULL;
    size_t wire2_len = 0;
    ZV_CHECK("receipt v2: serializes",
             vcs_package_build_serialize(&r, &wire2, &wire2_len) ==
                 VCS_PACKAGE_BUILD_OK);
    struct vcs_package_build_receipt back;
    ZV_CHECK("receipt v2: parse round-trips capsule",
             vcs_package_build_parse(wire2, wire2_len, &back) ==
                 VCS_PACKAGE_BUILD_OK &&
             back.schema_version == VCS_PACKAGE_BUILD_VERSION &&
             back.has_toolchain_capsule &&
             memcmp(back.toolchain_capsule_root, capsule_root, 32) == 0 &&
             back.output_count == r.output_count);
    struct vcs_package_build_receipt v1;
    ZV_CHECK("receipt v2: v1 twin builds",
             zv_receipt(&v1, package_root, recipe_root, "14.2.0", 0x40));
    uint8_t *wire1 = NULL;
    size_t wire1_len = 0;
    ZV_CHECK("receipt v2: v1 twin serializes",
             vcs_package_build_serialize(&v1, &wire1, &wire1_len) ==
                 VCS_PACKAGE_BUILD_OK);
    ZV_CHECK("receipt v2: v2 wire = v1 wire + 32 bytes",
             wire2_len == wire1_len + 32u);

    /* v1 wires still parse (old evidence is never orphaned), and a v1
     * wire with its version byte flipped to 2 is truncated, never
     * misparsed. */
    struct vcs_package_build_receipt old;
    ZV_CHECK("receipt v2: v1 wire still parses",
             vcs_package_build_parse(wire1, wire1_len, &old) ==
                 VCS_PACKAGE_BUILD_OK &&
             old.schema_version == VCS_PACKAGE_BUILD_VERSION_MIN &&
             !old.has_toolchain_capsule);
    wire1[8] = (uint8_t)VCS_PACKAGE_BUILD_VERSION;
    wire1[9] = 0;
    ZV_CHECK("receipt v2: relabeled v1 wire fails closed",
             vcs_package_build_parse(wire1, wire1_len, &old) !=
                 VCS_PACKAGE_BUILD_OK);
    free(wire1);
    free(wire2);

    /* Byte-identity ignores the toolchain on purpose: the v1 twin and the
     * v2 capsule receipt commit the same outputs, so they MATCH — and
     * their receipt ids differ, so they count as two build events. */
    struct vcs_reproduce_verdict v;
    vcs_package_reproduce_compare(&v1, &r, &v);
    uint8_t id1[32], id2[32];
    bool ids = vcs_package_build_id(&v1, id1) == VCS_PACKAGE_BUILD_OK &&
               vcs_package_build_id(&r, id2) == VCS_PACKAGE_BUILD_OK;
    ZV_CHECK("receipt v2: cross-schema reproduction MATCHes, ids differ",
             v.reproduced && v.rule == VCS_REPRODUCE_MATCH && ids &&
             memcmp(id1, id2, 32) != 0);
    return failures;
}

static int t_reproduce(void)
{
    int failures = 0;
    uint8_t package_root[32], recipe_root[32];
    zv_pattern_root(0x50, package_root);
    zv_pattern_root(0x51, recipe_root);

    /* Byte-identical outputs reproduce — including the third-party case:
     * a different compiler version (a distinct receipt id, so a genuinely
     * separate build event) committing the same output set. */
    struct vcs_package_build_receipt ref, same, third;
    ZV_CHECK("reproduce: receipt fixtures build",
             zv_receipt(&ref, package_root, recipe_root, "14.2.0", 0x40) &&
             zv_receipt(&same, package_root, recipe_root, "14.2.0", 0x40) &&
             zv_receipt(&third, package_root, recipe_root,
                        "15.0.1-third-party", 0x40));
    struct vcs_reproduce_verdict v;
    vcs_package_reproduce_compare(&ref, &same, &v);
    ZV_CHECK("reproduce: identical receipts MATCH",
             v.reproduced && v.rule == VCS_REPRODUCE_MATCH &&
             v.detail[0] == '\0');
    vcs_package_reproduce_compare(&ref, &third, &v);
    uint8_t id_ref[32], id_third[32];
    bool ids = vcs_package_build_id(&ref, id_ref) == VCS_PACKAGE_BUILD_OK &&
               vcs_package_build_id(&third, id_third) == VCS_PACKAGE_BUILD_OK;
    ZV_CHECK("reproduce: third-party toolchain MATCH, distinct ids",
             v.reproduced && v.rule == VCS_REPRODUCE_MATCH && ids &&
             memcmp(id_ref, id_third, 32) != 0);

    /* Every divergence is named, loudly, with the path in the detail. */
    struct vcs_package_build_receipt bad;
    ZV_CHECK("reproduce: diverging fixture builds",
             zv_receipt(&bad, package_root, recipe_root, "14.2.0", 0x99));
    vcs_package_reproduce_compare(&ref, &bad, &v);
    ZV_CHECK("reproduce: hash divergence named with path and hashes",
             !v.reproduced &&
             v.rule == VCS_REPRODUCE_OUTPUT_HASH_MISMATCH &&
             strstr(v.detail, "include/add.h") != NULL &&
             strstr(v.detail, "expected sha3") != NULL);

    struct vcs_package_build_receipt short_build;
    vcs_package_build_receipt_init(&short_build);
    memcpy(short_build.package_root, package_root, 32);
    memcpy(short_build.recipe_root, recipe_root, 32);
    zv_pattern_root(0x77, short_build.lock_root);
    snprintf(short_build.compiler_id, sizeof(short_build.compiler_id),
             "gcc");
    snprintf(short_build.compiler_version,
             sizeof(short_build.compiler_version), "14.2.0");
    snprintf(short_build.flags, sizeof(short_build.flags), "-std=c23 -O1");
    short_build.result_class = (uint8_t)VCS_PACKAGE_BUILD_RESULT_TEST_PASS;
    short_build.isolation = (uint8_t)VCS_PACKAGE_BUILD_ISOLATION_FULL;
    short_build.test_ran = true;
    uint8_t hdr_hash[32];
    zv_pattern_root(0x40, hdr_hash);
    ZV_CHECK("reproduce: short fixture builds",
             vcs_package_build_add_output(&short_build, "include/add.h",
                                          hdr_hash, 100) ==
                 VCS_PACKAGE_BUILD_OK);
    vcs_package_reproduce_compare(&ref, &short_build, &v);
    ZV_CHECK("reproduce: missing output named",
             !v.reproduced && v.rule == VCS_REPRODUCE_OUTPUT_MISSING &&
             strstr(v.detail, "lib/libaddpkg.a") != NULL);
    vcs_package_reproduce_compare(&short_build, &ref, &v);
    ZV_CHECK("reproduce: unexpected output named",
             !v.reproduced && v.rule == VCS_REPRODUCE_OUTPUT_UNEXPECTED &&
             strstr(v.detail, "lib/libaddpkg.a") != NULL);

    struct vcs_package_build_receipt other;
    ZV_CHECK("reproduce: root fixtures build",
             zv_receipt(&other, package_root, recipe_root, "14.2.0", 0x40));
    zv_pattern_root(0x52, other.recipe_root);
    vcs_package_reproduce_compare(&ref, &other, &v);
    ZV_CHECK("reproduce: recipe root divergence named",
             !v.reproduced && v.rule == VCS_REPRODUCE_RECIPE_ROOT_MISMATCH);
    ZV_CHECK("reproduce: recipe fixture rebuilds",
             zv_receipt(&other, package_root, recipe_root, "14.2.0", 0x40));
    zv_pattern_root(0x53, other.lock_root);
    vcs_package_reproduce_compare(&ref, &other, &v);
    ZV_CHECK("reproduce: lock root divergence named",
             !v.reproduced && v.rule == VCS_REPRODUCE_LOCK_ROOT_MISMATCH);
    ZV_CHECK("reproduce: dep fixture rebuilds",
             zv_receipt(&other, package_root, recipe_root, "14.2.0", 0x40));
    uint8_t dep[32];
    zv_pattern_root(0x54, dep);
    ZV_CHECK("reproduce: dep adds",
             vcs_package_build_add_dep(&other, dep) ==
                 VCS_PACKAGE_BUILD_OK);
    vcs_package_reproduce_compare(&ref, &other, &v);
    ZV_CHECK("reproduce: dependency set divergence named",
             !v.reproduced && v.rule == VCS_REPRODUCE_DEP_SET_MISMATCH);

    /* A failing build has nothing to reproduce (no vacuous MATCH on an
     * empty output set), and a non-canonical receipt is invalid. */
    ZV_CHECK("reproduce: fail fixture rebuilds",
             zv_receipt(&other, package_root, recipe_root, "14.2.0", 0x40));
    other.result_class = (uint8_t)VCS_PACKAGE_BUILD_RESULT_BUILD_FAIL;
    other.test_ran = false;
    other.test_exit_code = 0;
    vcs_package_reproduce_compare(&other, &ref, &v);
    ZV_CHECK("reproduce: failing reference named, never vacuous",
             !v.reproduced &&
             v.rule == VCS_REPRODUCE_REFERENCE_NOT_INSTALLABLE);
    vcs_package_reproduce_compare(&ref, &other, &v);
    ZV_CHECK("reproduce: failing rebuild named",
             !v.reproduced &&
             v.rule == VCS_REPRODUCE_REBUILD_NOT_INSTALLABLE);
    struct vcs_package_build_receipt zeroed;
    memset(&zeroed, 0, sizeof(zeroed));
    vcs_package_reproduce_compare(&zeroed, &ref, &v);
    ZV_CHECK("reproduce: invalid reference named",
             !v.reproduced && v.rule == VCS_REPRODUCE_REFERENCE_INVALID);
    ZV_CHECK("reproduce: rule strings stable",
             strcmp(vcs_reproduce_rule_string(VCS_REPRODUCE_MATCH),
                    "match") == 0 &&
             strcmp(vcs_reproduce_rule_string(
                        VCS_REPRODUCE_OUTPUT_HASH_MISMATCH),
                    "output-hash-mismatch") == 0);

    /* ── the receipts-directory scan ── */
    char base[4400];
    snprintf(base, sizeof(base), "test-tmp/zv_repro_%ld", (long)getpid());
    zv_rm_rf(base);
    char missing[4400];
    snprintf(missing, sizeof(missing), "%s/no-such-dir", base);
    struct vcs_reproduce_report rep;
    ZV_CHECK("reproduce: a missing receipts dir is an empty report",
             vcs_package_reproduce_scan(missing, package_root, recipe_root,
                                        &rep) &&
             !rep.reproduced && rep.matching == 0 && rep.row_count == 0);

    char receipts_dir[4400];
    snprintf(receipts_dir, sizeof(receipts_dir), "%s/receipts", base);
    ZV_CHECK("reproduce: one build recorded, none reproduced",
             zv_store_receipt(receipts_dir, &ref) &&
             vcs_package_reproduce_scan(receipts_dir, package_root,
                                        recipe_root, &rep) &&
             !rep.reproduced && rep.matching == 1 && rep.row_count == 1 &&
             rep.rows[0].reference);
    ZV_CHECK("reproduce: two distinct builds agreeing reproduce",
             zv_store_receipt(receipts_dir, &third) &&
             vcs_package_reproduce_scan(receipts_dir, package_root,
                                        recipe_root, &rep) &&
             rep.reproduced && rep.matching == 2 && rep.row_count == 2 &&
             rep.rows[0].reference && !rep.rows[1].reference &&
             rep.rows[1].rule == VCS_REPRODUCE_MATCH);
    /* A foreign package's receipt in the same dir is not counted. */
    uint8_t foreign_root[32];
    zv_pattern_root(0x5f, foreign_root);
    struct vcs_package_build_receipt foreign;
    ZV_CHECK("reproduce: foreign receipt files but never matches",
             zv_receipt(&foreign, foreign_root, recipe_root, "14.2.0",
                        0x40) &&
             zv_store_receipt(receipts_dir, &foreign) &&
             vcs_package_reproduce_scan(receipts_dir, package_root,
                                        recipe_root, &rep) &&
             rep.reproduced && rep.matching == 2);
    /* A diverging third build kills the verdict and is named by rule. */
    ZV_CHECK("reproduce: diverging third build files",
             zv_store_receipt(receipts_dir, &bad));
    bool scan_ok = vcs_package_reproduce_scan(receipts_dir, package_root,
                                              recipe_root, &rep);
    bool named = false;
    for (size_t i = 0; i < rep.row_count; i++)
        if (rep.rows[i].rule == VCS_REPRODUCE_OUTPUT_HASH_MISMATCH)
            named = true;
    ZV_CHECK("reproduce: a diverging build is rejected loudly",
             scan_ok && !rep.reproduced && rep.matching == 3 && named);

    /* ── toolchain-capsule diversity: HOW independent the evidence is ──
     * Fresh receipts dirs per scenario; all fixtures reuse the agreeing
     * output set (out_seed 0x40) so only the capsule dimension moves. */
    uint8_t cap_a[32], cap_b[32];
    zv_pattern_root(0x61, cap_a);
    zv_pattern_root(0x62, cap_b);
    struct vcs_package_build_receipt c1, c2;
    char capdir[4400];

    /* (a) two matching v2 receipts pinning the SAME capsule: reproduced,
     * one distinct toolchain, NOT cross-toolchain. */
    bool cap_fix =
        zv_receipt(&c1, package_root, recipe_root, "14.2.0", 0x40) &&
        zv_receipt(&c2, package_root, recipe_root, "15.0.1", 0x40) &&
        vcs_package_build_set_toolchain_capsule(&c1, cap_a) ==
            VCS_PACKAGE_BUILD_OK &&
        vcs_package_build_set_toolchain_capsule(&c2, cap_a) ==
            VCS_PACKAGE_BUILD_OK;
    ZV_CHECK("reproduce: same-capsule fixtures build", cap_fix);
    snprintf(capdir, sizeof(capdir), "%s/caps_same", base);
    ZV_CHECK("reproduce: same capsule is one toolchain, never cross",
             cap_fix && zv_store_receipt(capdir, &c1) &&
             zv_store_receipt(capdir, &c2) &&
             vcs_package_reproduce_scan(capdir, package_root, recipe_root,
                                        &rep) &&
             rep.reproduced && rep.distinct_toolchains == 1 &&
             !rep.cross_toolchain && rep.row_count == 2 &&
             rep.rows[0].has_toolchain_capsule &&
             rep.rows[1].has_toolchain_capsule &&
             memcmp(rep.rows[0].toolchain_capsule_root, cap_a, 32) == 0);

    /* (b) two matching v2 receipts pinning DIFFERENT capsules: the strong
     * claim — two toolchains produced byte-identical outputs. */
    cap_fix =
        zv_receipt(&c1, package_root, recipe_root, "14.2.0", 0x40) &&
        zv_receipt(&c2, package_root, recipe_root, "15.0.1", 0x40) &&
        vcs_package_build_set_toolchain_capsule(&c1, cap_a) ==
            VCS_PACKAGE_BUILD_OK &&
        vcs_package_build_set_toolchain_capsule(&c2, cap_b) ==
            VCS_PACKAGE_BUILD_OK;
    ZV_CHECK("reproduce: cross-capsule fixtures build", cap_fix);
    snprintf(capdir, sizeof(capdir), "%s/caps_diff", base);
    ZV_CHECK("reproduce: two distinct capsules report cross_toolchain",
             cap_fix && zv_store_receipt(capdir, &c1) &&
             zv_store_receipt(capdir, &c2) &&
             vcs_package_reproduce_scan(capdir, package_root, recipe_root,
                                        &rep) &&
             rep.reproduced && rep.distinct_toolchains == 2 &&
             rep.cross_toolchain);

    /* (c) a capsule-less (v1) matching pair: byte-identity proven,
     * toolchain independence not claimed. */
    cap_fix =
        zv_receipt(&c1, package_root, recipe_root, "14.2.0", 0x40) &&
        zv_receipt(&c2, package_root, recipe_root, "15.0.1", 0x40);
    snprintf(capdir, sizeof(capdir), "%s/caps_v1", base);
    ZV_CHECK("reproduce: v1 receipts add zero toolchain diversity",
             cap_fix && zv_store_receipt(capdir, &c1) &&
             zv_store_receipt(capdir, &c2) &&
             vcs_package_reproduce_scan(capdir, package_root, recipe_root,
                                        &rep) &&
             rep.reproduced && rep.distinct_toolchains == 0 &&
             !rep.cross_toolchain &&
             !rep.rows[0].has_toolchain_capsule);

    /* (d) a NON-matching row never inflates the counts: an agreeing
     * same-capsule pair plus a diverging third build pinning a different
     * capsule still reads one toolchain, not cross. */
    cap_fix =
        zv_receipt(&c1, package_root, recipe_root, "14.2.0", 0x40) &&
        zv_receipt(&c2, package_root, recipe_root, "15.0.1", 0x40) &&
        vcs_package_build_set_toolchain_capsule(&c1, cap_a) ==
            VCS_PACKAGE_BUILD_OK &&
        vcs_package_build_set_toolchain_capsule(&c2, cap_a) ==
            VCS_PACKAGE_BUILD_OK;
    struct vcs_package_build_receipt cdiv;
    cap_fix = cap_fix &&
        zv_receipt(&cdiv, package_root, recipe_root, "15.0.2", 0x99) &&
        vcs_package_build_set_toolchain_capsule(&cdiv, cap_b) ==
            VCS_PACKAGE_BUILD_OK;
    ZV_CHECK("reproduce: diverging-capsule fixtures build", cap_fix);
    snprintf(capdir, sizeof(capdir), "%s/caps_mixed", base);
    ZV_CHECK("reproduce: a diverging row's capsule never inflates diversity",
             cap_fix && zv_store_receipt(capdir, &c1) &&
             zv_store_receipt(capdir, &c2) &&
             zv_store_receipt(capdir, &cdiv) &&
             vcs_package_reproduce_scan(capdir, package_root, recipe_root,
                                        &rep) &&
             !rep.reproduced && rep.matching == 3 &&
             rep.distinct_toolchains == 1 && !rep.cross_toolchain);
    zv_rm_rf(base);

    /* ── the eligibility gates: reproduction outranks the quorum ── */
    {
        struct vcs_reward_eligibility_input in;
        memset(&in, 0, sizeof(in));
        in.manifest_parsed = true;
        in.root_matches = true;
        in.chunks_checked = true;
        in.chunks_verified = 1;
        in.chunks_total = 1;
        in.release_verifies = true;
        in.license_accepted = true;
        in.lineage_valid = true;
        in.lineage_detail = "root release (no parent)";
        /* NO quorum facts at all — reproduction alone carries gates 5-8. */
        in.reproduction_verified = true;
        struct vcs_reward_eligibility e;
        vcs_reward_eligibility_evaluate(&in, &e);
        ZV_CHECK("reproduce: eligible on reproduction without a quorum",
                 e.eligible && e.failed_count == 0 &&
                 e.reproduction_verified &&
                 e.gates[VCS_REWARD_GATE_GCC_BUILD].passed &&
                 e.gates[VCS_REWARD_GATE_CLANG_BUILD].passed &&
                 e.gates[VCS_REWARD_GATE_TESTS_PASS].passed &&
                 e.gates[VCS_REWARD_GATE_VERIFIER_QUORUM].passed &&
                 strstr(e.gates[VCS_REWARD_GATE_VERIFIER_QUORUM].detail,
                        "reproduction") != NULL);
        in.reproduction_verified = false;
        vcs_reward_eligibility_evaluate(&in, &e);
        ZV_CHECK("reproduce: without it, gates 5-8 fail as before",
                 !e.eligible && e.failed_count == 4 &&
                 !e.reproduction_verified &&
                 strstr(e.gates[VCS_REWARD_GATE_VERIFIER_QUORUM].detail,
                        "no recorded reproduction") != NULL);
    }

    /* ── owner directive pin (2026-08-25): cross-toolchain diversity is
     * EVIDENCE, NEVER A GATE, all the way through to reward eligibility.
     * The owner ruled: "RECORD cross-toolchain diversity as evidence
     * whenever it is observed, but NEVER GATE PUBLICATION ON IT. A
     * two-toolchain requirement locks out every solo publisher working
     * on one machine, which betrays runs-anywhere. Diversity accumulates
     * from witnesses over time. It is a STRENGTH SCORE, NOT A DOOR."
     * struct vcs_reward_eligibility_input (contexts/commons/modules/vcs/include/vcs/
     * package_eligible.h) does not even carry a toolchain-diversity
     * field — it takes only reproduction_verified — so drive it from a
     * REAL vcs_package_reproduce_scan() report end to end and prove the
     * verdict a solo, single-toolchain publisher gets is identical to a
     * two-toolchain publisher's. */
    {
        char ebase[4400];
        snprintf(ebase, sizeof(ebase), "%s/eligibility_toolchain", base);
        zv_rm_rf(ebase);
        uint8_t ecap_a[32], ecap_b[32];
        zv_pattern_root(0x81, ecap_a);
        zv_pattern_root(0x82, ecap_b);

        /* (a)+(b) SOLO: two matching receipts pinning the SAME capsule —
         * one publisher, one machine, rebuilt twice. Must still be
         * eligible, and the scan must still honestly report
         * distinct_toolchains=1, cross_toolchain=false (recording never
         * stops just because it doesn't gate). */
        struct vcs_package_build_receipt e1, e2;
        char edir_solo[4400];
        snprintf(edir_solo, sizeof(edir_solo), "%s/solo", ebase);
        struct vcs_reproduce_report erep;
        bool solo_scan_ok =
            zv_receipt(&e1, package_root, recipe_root, "14.2.0", 0x40) &&
            zv_receipt(&e2, package_root, recipe_root, "15.0.1", 0x40) &&
            vcs_package_build_set_toolchain_capsule(&e1, ecap_a) ==
                VCS_PACKAGE_BUILD_OK &&
            vcs_package_build_set_toolchain_capsule(&e2, ecap_a) ==
                VCS_PACKAGE_BUILD_OK &&
            zv_store_receipt(edir_solo, &e1) &&
            zv_store_receipt(edir_solo, &e2) &&
            vcs_package_reproduce_scan(edir_solo, package_root, recipe_root,
                                       &erep);
        ZV_CHECK("owner directive: solo single-toolchain scan reproduces "
                 "and honestly reports distinct_toolchains=1, "
                 "cross_toolchain=false",
                 solo_scan_ok && erep.reproduced &&
                 erep.distinct_toolchains == 1 && !erep.cross_toolchain);

        struct vcs_reward_eligibility_input ein;
        memset(&ein, 0, sizeof(ein));
        ein.manifest_parsed = true;
        ein.root_matches = true;
        ein.chunks_checked = true;
        ein.chunks_verified = 1;
        ein.chunks_total = 1;
        ein.release_verifies = true;
        ein.license_accepted = true;
        ein.lineage_valid = true;
        ein.lineage_detail = "root release (no parent)";
        ein.reproduction_verified = solo_scan_ok && erep.reproduced;
        struct vcs_reward_eligibility esolo;
        vcs_reward_eligibility_evaluate(&ein, &esolo);
        ZV_CHECK("owner directive: a solo single-toolchain reproduction "
                 "still earns FULL reward eligibility (cross-toolchain "
                 "diversity must be evidence, never a publication/"
                 "eligibility gate — owner directive)",
                 esolo.eligible && esolo.failed_count == 0 &&
                 esolo.reproduction_verified);

        /* (c) TWO capsules: strictly more evidence, same verdict. */
        struct vcs_package_build_receipt e3, e4;
        char edir_cross[4400];
        snprintf(edir_cross, sizeof(edir_cross), "%s/cross", ebase);
        struct vcs_reproduce_report erep2;
        bool cross_scan_ok =
            zv_receipt(&e3, package_root, recipe_root, "14.2.0", 0x40) &&
            zv_receipt(&e4, package_root, recipe_root, "15.0.1", 0x40) &&
            vcs_package_build_set_toolchain_capsule(&e3, ecap_a) ==
                VCS_PACKAGE_BUILD_OK &&
            vcs_package_build_set_toolchain_capsule(&e4, ecap_b) ==
                VCS_PACKAGE_BUILD_OK &&
            zv_store_receipt(edir_cross, &e3) &&
            zv_store_receipt(edir_cross, &e4) &&
            vcs_package_reproduce_scan(edir_cross, package_root, recipe_root,
                                       &erep2);
        ZV_CHECK("owner directive: two-capsule scan reports "
                 "distinct_toolchains=2, cross_toolchain=true",
                 cross_scan_ok && erep2.reproduced &&
                 erep2.distinct_toolchains == 2 && erep2.cross_toolchain);
        ein.reproduction_verified = cross_scan_ok && erep2.reproduced;
        struct vcs_reward_eligibility ecross;
        vcs_reward_eligibility_evaluate(&ein, &ecross);
        ZV_CHECK("owner directive: two-toolchain evidence changes NO "
                 "eligibility verdict relative to the solo case above — "
                 "same eligible=true, strictly more evidence; diversity "
                 "is a strength score, not a door (owner directive)",
                 ecross.eligible == esolo.eligible &&
                 ecross.eligible && ecross.failed_count == 0 &&
                 erep.distinct_toolchains != erep2.distinct_toolchains);
        zv_rm_rf(ebase);
    }
    return failures;
}

static int t_command(void)
{
    int failures = 0;
    char datadir[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zv_cmd_%ld",
             (long)getpid());
    char store[4400];
    snprintf(store, sizeof(store), "%s/zcode", datadir);
    zv_rm_rf(datadir);

    uint8_t package_root[32], release_id[32], recipe_root[32];
    bool fixture = zv_publish_fixture(
        store,
        "#include \"add.h\"\nint add(int a, int b) { return a + b; }\n",
        "#include \"add.h\"\nint main(void) { return add(2, 3) == 5 ? 0 : 1; }\n",
        package_root, release_id, recipe_root);
    ZV_CHECK("command: fixture store publishes", fixture);
    if (!fixture)
        return failures + 1;
    char root_hex[65];
    zv_hex_enc(package_root, 32, root_hex);

    /* No allowlist -> named rejection. */
    {
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, root_hex);
        zcl_native_handle_zcode_package_verify(&c.request, &c.reply);
        ZV_CHECK("command: NO_APPROVED_VERIFIERS without an allowlist",
                 strcmp(c.reply.error.code, "NO_APPROVED_VERIFIERS") == 0);
        zv_cmd_free(&c);
    }

    /* One attestation short of quorum. */
    ZV_CHECK("command: allowlist writes", zv_write_policy(store));
    ZV_CHECK("command: attestation A persists",
             zv_store_attestation(store, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                  package_root, release_id, recipe_root,
                                  0x22));
    {
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, root_hex);
        zcl_native_handle_zcode_package_verify(&c.request, &c.reply);
        ZV_CHECK("command: one signer is not a quorum",
                 !json_get_bool(json_get(&c.reply.data, "verified")) &&
                 !json_get_bool(json_get(&c.reply.data, "quorum_reached")) &&
                 json_get_int(json_get(&c.reply.data, "quorum_signers")) == 1);
        zv_cmd_free(&c);
    }

    /* Two approved matching attestations -> verified. */
    ZV_CHECK("command: attestation B persists",
             zv_store_attestation(store, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                  package_root, release_id, recipe_root,
                                  0x33));
    {
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, root_hex);
        zcl_native_handle_zcode_package_verify(&c.request, &c.reply);
        const char *qclass =
            json_get_str(json_get(&c.reply.data, "quorum_class"));
        const struct json_value *rows = json_get(&c.reply.data, "rows");
        ZV_CHECK("command: 2-of-N approved matching verifies",
                 json_get_bool(json_get(&c.reply.data, "verified")) &&
                 json_get_bool(json_get(&c.reply.data, "quorum_reached")) &&
                 json_get_int(json_get(&c.reply.data, "quorum_signers")) == 2 &&
                 qclass && strcmp(qclass, "test-pass") == 0 &&
                 json_get_int(json_get(&c.reply.data,
                                       "attestations_scanned")) == 2 &&
                 rows && json_at(rows, 1) != NULL);
        zv_cmd_free(&c);
    }

    /* A third, unapproved attestation is named and changes nothing. */
    ZV_CHECK("command: unapproved attestation persists",
             zv_store_attestation(store, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                  package_root, release_id, recipe_root,
                                  0x44));
    {
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, root_hex);
        zcl_native_handle_zcode_package_verify(&c.request, &c.reply);
        const struct json_value *rows = json_get(&c.reply.data, "rows");
        /* readdir order is unspecified — find the unapproved row wherever
         * it landed. */
        bool named_unapproved = false;
        for (size_t i = 0; rows && json_at(rows, i); i++) {
            const char *rule =
                json_get_str(json_get(json_at(rows, i), "rule"));
            if (rule && strcmp(rule, "signer-not-approved") == 0)
                named_unapproved = true;
        }
        ZV_CHECK("command: unapproved signer named in rows",
                 json_get_bool(json_get(&c.reply.data, "verified")) &&
                 json_get_int(json_get(&c.reply.data,
                                       "attestations_scanned")) == 3 &&
                 named_unapproved);
        zv_cmd_free(&c);
    }

    /* Rejections. */
    {
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "zz");
        zcl_native_handle_zcode_package_verify(&c.request, &c.reply);
        ZV_CHECK("command: BAD_ROOT",
                 strcmp(c.reply.error.code, "BAD_ROOT") == 0);
        zv_cmd_free(&c);
    }
    {
        uint8_t other[32];
        zv_pattern_root(0x55, other);
        char other_hex[65];
        zv_hex_enc(other, 32, other_hex);
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, other_hex);
        zcl_native_handle_zcode_package_verify(&c.request, &c.reply);
        ZV_CHECK("command: UNKNOWN_PACKAGE",
                 strcmp(c.reply.error.code, "UNKNOWN_PACKAGE") == 0);
        zv_cmd_free(&c);
    }

    /* The reproduction object: two distinct build receipts committing
     * byte-identical output sets reproduce; a diverging third receipt
     * kills the verdict and is named by rule. The two agreeing receipts
     * pin DIFFERENT toolchain capsules, so the response must also carry
     * the strong diversity claim (distinct_toolchains=2, cross_toolchain)
     * — and that telemetry survives a rejected verdict. */
    {
        char receipts_dir[4400];
        snprintf(receipts_dir, sizeof(receipts_dir), "%s/receipts", store);
        uint8_t cap1[32], cap2[32];
        zv_pattern_root(0x71, cap1);
        zv_pattern_root(0x72, cap2);
        struct vcs_package_build_receipt r1, r2;
        ZV_CHECK("command: reproduction receipts build",
                 zv_receipt(&r1, package_root, recipe_root, "14.2.0",
                            0x40) &&
                 zv_receipt(&r2, package_root, recipe_root,
                            "15.0.1-third-party", 0x40) &&
                 vcs_package_build_set_toolchain_capsule(&r1, cap1) ==
                     VCS_PACKAGE_BUILD_OK &&
                 vcs_package_build_set_toolchain_capsule(&r2, cap2) ==
                     VCS_PACKAGE_BUILD_OK);
        ZV_CHECK("command: reproduction receipts persist",
                 zv_store_receipt(receipts_dir, &r1) &&
                 zv_store_receipt(receipts_dir, &r2));
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, root_hex);
        zcl_native_handle_zcode_package_verify(&c.request, &c.reply);
        const struct json_value *repro =
            json_get(&c.reply.data, "reproduction");
        ZV_CHECK("command: distinct matching receipts reproduce",
                 repro &&
                 json_get_bool(json_get(repro, "scanned_ok")) &&
                 json_get_bool(json_get(repro, "reproduced")) &&
                 json_get_int(json_get(repro, "matching_receipts")) == 2);
        ZV_CHECK("command: two pinned capsules report cross_toolchain",
                 repro &&
                 json_get_int(json_get(repro, "distinct_toolchains")) == 2 &&
                 json_get_bool(json_get(repro, "cross_toolchain")));
        zv_cmd_free(&c);

        struct vcs_package_build_receipt r3;
        ZV_CHECK("command: diverging receipt persists",
                 zv_receipt(&r3, package_root, recipe_root,
                            "14.2.0-tampered", 0x99) &&
                 zv_store_receipt(receipts_dir, &r3));
        struct zv_cmd c2;
        zv_cmd_init(&c2, datadir, root_hex);
        zcl_native_handle_zcode_package_verify(&c2.request, &c2.reply);
        const struct json_value *repro2 =
            json_get(&c2.reply.data, "reproduction");
        const struct json_value *rrows =
            repro2 ? json_get(repro2, "rows") : NULL;
        bool mismatch_named = false;
        for (size_t i = 0; rrows && json_at(rrows, i); i++) {
            const char *rule =
                json_get_str(json_get(json_at(rrows, i), "rule"));
            if (rule && strcmp(rule, "output-hash-mismatch") == 0)
                mismatch_named = true;
        }
        ZV_CHECK("command: diverging receipt rejected loudly",
                 repro2 &&
                 !json_get_bool(json_get(repro2, "reproduced")) &&
                 json_get_int(json_get(repro2, "matching_receipts")) == 3 &&
                 mismatch_named);
        ZV_CHECK("command: the diverging capsule-less row never inflates "
                 "diversity",
                 repro2 &&
                 json_get_int(json_get(repro2, "distinct_toolchains")) == 2 &&
                 json_get_bool(json_get(repro2, "cross_toolchain")));
        zv_cmd_free(&c2);
    }
    zv_rm_rf(datadir);
    return failures;
}

/* ── 3c. zcode package attest import: the third-party evidence loop ────
 * The only writer into attestations/ was the verifier program itself, on
 * its own filesystem. import closes the loop: a signed wire arrives as
 * hex input and is filed locally. Filing is NOT acceptance. */

/* Serialize + hex-encode one signed attestation for the import input. */
static bool zv_attest_wire_hex(struct vcs_package_attest *a, uint8_t cls,
                               const uint8_t package_root[32],
                               const uint8_t release_id[32],
                               const uint8_t recipe_root[32],
                               uint8_t signer_seed, char *hex_out,
                               uint8_t id_out[32])
{
    if (!zv_attest(a, cls, package_root, release_id, recipe_root,
                   signer_seed))
        return false;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool ok = vcs_package_attest_serialize(a, &wire, &wire_len) ==
                  VCS_PACKAGE_ATTEST_OK &&
              vcs_package_attest_id(a, id_out) == VCS_PACKAGE_ATTEST_OK;
    if (ok)
        zv_hex_enc(wire, wire_len, hex_out);
    free(wire);
    return ok;
}

static int t_attest_import(void)
{
    int failures = 0;
    char datadir[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zv_import_%ld",
             (long)getpid());
    char store[4400];
    snprintf(store, sizeof(store), "%s/zcode", datadir);
    zv_rm_rf(datadir);

    uint8_t package_root[32], release_id[32], recipe_root[32];
    bool fixture = zv_publish_fixture(
        store,
        "#include \"add.h\"\nint add(int a, int b) { return a + b; }\n",
        "#include \"add.h\"\nint main(void) { return add(2, 3) == 5 ? 0 : 1; }\n",
        package_root, release_id, recipe_root);
    ZV_CHECK("import: fixture store publishes", fixture);
    if (!fixture)
        return failures + 1;
    char root_hex[65];
    zv_hex_enc(package_root, 32, root_hex);
    ZV_CHECK("import: allowlist writes", zv_write_policy(store));

    /* (a) A third party's signed wire imports and is then counted by
     * verify. The attestation bytes are built in-memory here — the handler
     * is the ONLY writer into attestations/ in this test. */
    struct vcs_package_attest a;
    uint8_t id_a[32];
    char wire_hex[2 * VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES + 1];
    ZV_CHECK("import: attestation A wire builds",
             zv_attest_wire_hex(&a, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                package_root, release_id, recipe_root, 0x22,
                                wire_hex, id_a));
    char id_a_hex[65];
    zv_hex_enc(id_a, 32, id_a_hex);
    char signer_a_hex[67];
    zv_hex_enc(a.verifier_pubkey, 33, signer_a_hex);
    {
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "attestation_wire", wire_hex);
        zcl_native_handle_zcode_package_attest_import(&c.request, &c.reply);
        const char *aid =
            json_get_str(json_get(&c.reply.data, "attestation_id"));
        const char *signer =
            json_get_str(json_get(&c.reply.data, "signer_pubkey"));
        const char *class_name =
            json_get_str(json_get(&c.reply.data, "result_class"));
        const char *note = json_get_str(json_get(&c.reply.data, "note"));
        ZV_CHECK("import: valid wire files",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 json_get_bool(json_get(&c.reply.data, "filed")) &&
                 !json_get_bool(json_get(&c.reply.data, "already_present")) &&
                 aid && strcmp(aid, id_a_hex) == 0 &&
                 signer && strcmp(signer, signer_a_hex) == 0 &&
                 class_name && strcmp(class_name, "test-pass") == 0 &&
                 note && strstr(note, "filing is not acceptance") != NULL);
        zv_cmd_free(&c);
    }

    /* (b) Re-importing the identical wire is an idempotent no-op success. */
    {
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "attestation_wire", wire_hex);
        zcl_native_handle_zcode_package_attest_import(&c.request, &c.reply);
        ZV_CHECK("import: re-import is idempotent",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 !json_get_bool(json_get(&c.reply.data, "filed")) &&
                 json_get_bool(json_get(&c.reply.data, "already_present")));
        zv_cmd_free(&c);
    }

    /* A second approved signer's wire imported the same way completes the
     * quorum — import is the ONLY way these bytes reached the store. */
    struct vcs_package_attest b;
    uint8_t id_b[32];
    char wire_b_hex[2 * VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES + 1];
    ZV_CHECK("import: attestation B wire builds",
             zv_attest_wire_hex(&b, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                package_root, release_id, recipe_root, 0x33,
                                wire_b_hex, id_b));
    {
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "attestation_wire", wire_b_hex);
        zcl_native_handle_zcode_package_attest_import(&c.request, &c.reply);
        ZV_CHECK("import: second wire files",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 json_get_bool(json_get(&c.reply.data, "filed")));
        zv_cmd_free(&c);
    }
    {
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, root_hex);
        zcl_native_handle_zcode_package_verify(&c.request, &c.reply);
        ZV_CHECK("import: verify counts the imported wires",
                 json_get_bool(json_get(&c.reply.data, "verified")) &&
                 json_get_int(json_get(&c.reply.data, "quorum_signers")) == 2 &&
                 json_get_int(json_get(&c.reply.data,
                                       "attestations_scanned")) == 2);
        zv_cmd_free(&c);
    }

    /* (c) A wire tampered inside the signed region fails the signature
     * check with the rule named. */
    {
        char tampered[2 * VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES + 1];
        snprintf(tampered, sizeof(tampered), "%s", wire_hex);
        /* byte 20 sits inside package_root (offset 10..42) — signed. */
        tampered[2 * 20] = tampered[2 * 20] == '0' ? '1' : '0';
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "attestation_wire", tampered);
        zcl_native_handle_zcode_package_attest_import(&c.request, &c.reply);
        ZV_CHECK("import: tampered wire refused naming the signature rule",
                 c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
                 strcmp(c.reply.error.code, "ATTEST_SIGNATURE") == 0 &&
                 strcmp(c.reply.error.evidence,
                        vcs_package_attest_error_string(
                            VCS_PACKAGE_ATTEST_ERR_SIG_VERIFY)) == 0);
        zv_cmd_free(&c);
    }

    /* (d) A structurally invalid wire (corrupted magic) fails the parse
     * with the grammar rule named. */
    {
        char broken[2 * VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES + 1];
        snprintf(broken, sizeof(broken), "%s", wire_hex);
        broken[0] = wire_hex[0] == '5' ? '6' : '5'; /* 'Z' -> something else */
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "attestation_wire", broken);
        zcl_native_handle_zcode_package_attest_import(&c.request, &c.reply);
        ZV_CHECK("import: non-canonical wire refused naming the parse rule",
                 c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
                 strcmp(c.reply.error.code, "ATTEST_INVALID") == 0 &&
                 strcmp(c.reply.error.evidence,
                        vcs_package_attest_error_string(
                            VCS_PACKAGE_ATTEST_ERR_WIRE_MAGIC)) == 0);
        zv_cmd_free(&c);
    }

    /* (e) Filing is not acceptance: an attestation for a package this node
     * has never seen still files (the wire is self-consistent and signed);
     * verify then names the unknown package rather than crashing. */
    {
        uint8_t ghost_pkg[32], ghost_rel[32], ghost_recipe[32];
        zv_pattern_root(0x91, ghost_pkg);
        zv_pattern_root(0x92, ghost_rel);
        zv_pattern_root(0x93, ghost_recipe);
        struct vcs_package_attest g;
        uint8_t id_g[32];
        char wire_g_hex[2 * VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES + 1];
        ZV_CHECK("import: ghost attestation wire builds",
                 zv_attest_wire_hex(&g, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                    ghost_pkg, ghost_rel, ghost_recipe, 0x22,
                                    wire_g_hex, id_g));
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "attestation_wire", wire_g_hex);
        zcl_native_handle_zcode_package_attest_import(&c.request, &c.reply);
        ZV_CHECK("import: unseen package's attestation still files",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 json_get_bool(json_get(&c.reply.data, "filed")));
        zv_cmd_free(&c);

        char ghost_hex[65];
        zv_hex_enc(ghost_pkg, 32, ghost_hex);
        struct zv_cmd c2;
        zv_cmd_init(&c2, datadir, ghost_hex);
        zcl_native_handle_zcode_package_verify(&c2.request, &c2.reply);
        ZV_CHECK("import: verify names the unknown package",
                 c2.reply.status == ZCL_COMMAND_STATUS_FAILED &&
                 strcmp(c2.reply.error.code, "UNKNOWN_PACKAGE") == 0);
        zv_cmd_free(&c2);
    }

    zv_rm_rf(datadir);
    return failures;
}

/* ── 3d. zcode package attest offer/pull: the COMMAND layer ────────────
 * The transport library beneath these two leaves is covered by
 * test_zcode_attest_transport. What is covered HERE is the operator
 * surface built on top of it: the two publish inputs `offer` must return
 * together, and the row discipline `pull` must keep when one pointer in a
 * set is hostile or unreachable.
 *
 * Neither leaf may open the live datadir: every case runs on a
 * ./test-tmp tree from the harness helper. `pull` reaches the network
 * through two existing seams and no socket — the DHT record lookup goes
 * through node_rpc_client's test hook, and the per-blob fetch through
 * zcl_native_zcode_discovery_test_backend. */

/* The pointer records the stubbed DHT lookup answers with, and what the
 * stub observed about the query it was asked. */
static const char *g_zv_pointer_records = "[]";
static bool g_zv_pointer_query_exact;
static unsigned g_zv_record_begin_calls;

static char *zv_pull_rpc_hook(const char *method, const char *params_json)
{
    if (strcmp(method, "zcode_dht_record_begin") == 0) {
        g_zv_record_begin_calls++;
        /* The pull must ask the ONE key that means "who attested this
         * package": kind=pointer in the attestation namespace, at the
         * caller's package root. A stub that answered any query would
         * let a wrong lookup pass. */
        g_zv_pointer_query_exact =
            params_json != NULL &&
            strstr(params_json, "\"kind\":\"pointer\"") != NULL &&
            strstr(params_json,
                   "\"namespace\":\"" VCS_PACKAGE_ATTEST_DHT_NAMESPACE
                   "\"") != NULL;
        return zcl_strdup("{\"ok\":true,"
                          "\"lookup_id\":"
                          "\"0123456789abcdef0123456789abcdef\","
                          "\"owner_token\":"
                          "\"fedcba9876543210fedcba9876543210\"}",
                          "test.zcode_verify.record_begin");
    }
    if (strcmp(method, "zcode_dht_record_poll") == 0) {
        char body[8192];
        int n = snprintf(body, sizeof(body),
                         "{\"ok\":true,\"state\":\"complete\","
                         "\"records\":%s}", g_zv_pointer_records);
        return (n > 0 && (size_t)n < sizeof(body))
            ? zcl_strdup(body, "test.zcode_verify.record_poll") : NULL;
    }
    if (strcmp(method, "zcode_dht_record_cancel") == 0)
        return zcl_strdup("{\"ok\":true}",
                          "test.zcode_verify.record_cancel");
    return zcl_strdup("{\"ok\":false,\"code\":\"UNEXPECTED_RPC\"}",
                      "test.zcode_verify.unexpected_rpc");
}

/* The daemon-side fetch seam: one authenticated provider answers for any
 * canonical transport root in the attestation namespace, and the bytes
 * are already here. The blob layer — not this stub — remains the
 * authority on whether the bytes actually exist locally. */
static bool zv_discover_attest_provider(struct json_value *selector,
                                        struct json_value *result)
{
    const char *kind = json_get_str(json_get(selector, "kind"));
    const char *ns = json_get_str(json_get(selector, "namespace"));
    const char *root = json_get_str(json_get(selector, "transport_root"));
    if (!kind || strcmp(kind, "provider") != 0 ||
        !ns || strcmp(ns, VCS_PACKAGE_ATTEST_DHT_NAMESPACE) != 0 ||
        !root || strlen(root) != 64)
        return false;
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_int(result, "count", 1);
    return true;
}

static bool zv_route_attest_provider(struct json_value *selector,
                                     struct json_value *result)
{
    (void)selector;
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_int(result, "authenticated_providers", 1);
    (void)json_push_kv_str(result, "fetch_result", "already-complete");
    (void)json_push_kv_bool(result, "restricted", true);
    return true;
}

/* Nobody serves these bytes: discovery finds no provider record at all.
 * This is the "pointers exist, bytes unreachable" half of the split the
 * pull report is required to keep distinct from "nobody attested". */
static bool zv_discover_no_provider(struct json_value *selector,
                                    struct json_value *result)
{
    (void)selector;
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_int(result, "count", 0);
    return false;
}

/* One pull row, found by the transport root it names. */
static const struct json_value *zv_row_for(const struct json_value *rows,
                                           const char *transport_hex)
{
    if (!rows || rows->type != JSON_ARR)
        return NULL;
    for (size_t i = 0; i < json_size(rows); i++) {
        const struct json_value *row = json_at(rows, i);
        const char *r = row ? json_get_str(json_get(row, "transport_root"))
                            : NULL;
        if (r && strcmp(r, transport_hex) == 0)
            return row;
    }
    return NULL;
}

static bool zv_str_is(const struct json_value *v, const char *key,
                      const char *want)
{
    const char *s = json_get_str(json_get(v, key));
    return s && strcmp(s, want) == 0;
}

static bool zv_str_has(const struct json_value *v, const char *key,
                       const char *needle)
{
    const char *s = json_get_str(json_get(v, key));
    return s && strstr(s, needle) != NULL;
}

/* File one signed attestation, then run the OFFER handler over it so its
 * exact bytes become a blob in the datadir store. Hands back the id and
 * the transport root the handler reported, and (deliberately) removes the
 * local attestations/ copy afterwards when `unfile` is set — that is the
 * state a receiving node is really in: the blob is reachable, the
 * attestation is not yet filed. */
static bool zv_offer_attestation(const char *datadir, const char *store,
                                 uint8_t cls, const uint8_t package_root[32],
                                 const uint8_t release_id[32],
                                 const uint8_t recipe_root[32],
                                 uint8_t signer_seed, bool unfile,
                                 char id_hex_out[65],
                                 char transport_hex_out[65])
{
    struct vcs_package_attest a;
    if (!zv_attest(&a, cls, package_root, release_id, recipe_root,
                   signer_seed))
        return false;
    uint8_t id[32];
    if (vcs_package_attest_id(&a, id) != VCS_PACKAGE_ATTEST_OK)
        return false;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_attest_serialize(&a, &wire, &wire_len) !=
        VCS_PACKAGE_ATTEST_OK)
        return false;
    zv_hex_enc(id, 32, id_hex_out);
    char path[4400];
    snprintf(path, sizeof(path), "%s/attestations/%s", store, id_hex_out);
    bool ok = zv_write_file(path, wire, wire_len, 0600);
    free(wire);
    if (!ok)
        return false;

    struct zv_cmd c;
    zv_cmd_init(&c, datadir, "");
    (void)json_push_kv_str(&c.input, "attestation_id", id_hex_out);
    zcl_native_handle_zcode_package_attest_offer(&c.request, &c.reply);
    const char *tr = json_get_str(json_get(&c.reply.data, "transport_root"));
    ok = c.reply.status == ZCL_COMMAND_STATUS_PASSED && tr &&
         strlen(tr) == 64;
    if (ok)
        snprintf(transport_hex_out, 65, "%s", tr);
    zv_cmd_free(&c);
    if (ok && unfile)
        ok = unlink(path) == 0;
    return ok;
}

static int t_attest_offer(void)
{
    int failures = 0;
    char datadir[1024];
    test_make_tmpdir(datadir, sizeof(datadir), "zcode_verify", "attest-offer");
    char store[4400];
    snprintf(store, sizeof(store), "%s/zcode", datadir);

    uint8_t package_root[32], release_id[32], recipe_root[32];
    bool fixture = zv_publish_fixture(
        store,
        "#include \"add.h\"\nint add(int a, int b) { return a + b; }\n",
        "#include \"add.h\"\nint main(void) { return add(2, 3) == 5 ? 0 : 1; }\n",
        package_root, release_id, recipe_root);
    ZV_CHECK("offer: fixture store publishes", fixture);
    if (!fixture) {
        test_rm_rf_recursive(datadir);
        return failures + 1;
    }
    char package_hex[65];
    zv_hex_enc(package_root, 32, package_hex);

    /* One filed attestation, written by the fixture — the handler is the
     * only thing that turns it into a reachable blob. */
    struct vcs_package_attest a;
    uint8_t id[32];
    bool built = zv_attest(&a, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                           package_root, release_id, recipe_root, 0x22) &&
                 vcs_package_attest_id(&a, id) == VCS_PACKAGE_ATTEST_OK;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    built = built && vcs_package_attest_serialize(&a, &wire, &wire_len) ==
                         VCS_PACKAGE_ATTEST_OK;
    char id_hex[65] = "";
    char expect_transport_hex[65] = "";
    if (built) {
        zv_hex_enc(id, 32, id_hex);
        char path[4400];
        snprintf(path, sizeof(path), "%s/attestations/%s", store, id_hex);
        built = zv_write_file(path, wire, wire_len, 0600);
        /* The transport root is the BLOB root of these exact bytes,
         * derived here independently of the transport layer. */
        uint8_t expect[32];
        built = built && vcs_blob_root(wire, wire_len, expect);
        if (built)
            zv_hex_enc(expect, 32, expect_transport_hex);
    }
    free(wire);
    ZV_CHECK("offer: filed attestation fixture builds", built);
    if (!built) {
        test_rm_rf_recursive(datadir);
        return failures + 1;
    }

    char first_transport_hex[65] = "";
    /* (a) The happy path returns BOTH publish inputs. Publishing only one
     * is a silent no-op at pull time — pointer-only means a puller learns
     * which blob to want and finds nobody serving it, provider-only means
     * the bytes are reachable and nobody knows to ask — so a test that
     * accepted one would prove nothing this pairing exists to prevent. */
    {
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "attestation_id", id_hex);
        zcl_native_handle_zcode_package_attest_offer(&c.request, &c.reply);
        const char *transport =
            json_get_str(json_get(&c.reply.data, "transport_root"));
        if (transport && strlen(transport) == 64)
            snprintf(first_transport_hex, sizeof(first_transport_hex), "%s",
                     transport);
        const struct json_value *provider =
            json_get(&c.reply.data, "provider_publish_input");
        const struct json_value *pointer =
            json_get(&c.reply.data, "pointer_publish_input");
        ZV_CHECK("offer: identifies the attestation and its transport root",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 zv_str_is(&c.reply.data, "attestation_id", id_hex) &&
                 zv_str_is(&c.reply.data, "package_root", package_hex) &&
                 zv_str_is(&c.reply.data, "result_class", "test-pass") &&
                 zv_str_is(&c.reply.data, "namespace",
                           VCS_PACKAGE_ATTEST_DHT_NAMESPACE));
        ZV_CHECK("offer: transport_root is the blob root of the exact wire",
                 transport && strcmp(transport, expect_transport_hex) == 0 &&
                 strcmp(transport, id_hex) != 0);
        ZV_CHECK("offer: BOTH publish inputs are returned",
                 provider != NULL && pointer != NULL);
        ZV_CHECK("offer: the provider input says 'ask me for these bytes'",
                 provider && zv_str_is(provider, "mode", "plan") &&
                 zv_str_is(provider, "kind", "provider") &&
                 zv_str_is(provider, "namespace",
                           VCS_PACKAGE_ATTEST_DHT_NAMESPACE) &&
                 transport &&
                 zv_str_is(provider, "transport_root", transport) &&
                 json_get(provider, "semantic_root") == NULL);
        ZV_CHECK("offer: the pointer input binds the package to the blob",
                 pointer && zv_str_is(pointer, "mode", "plan") &&
                 zv_str_is(pointer, "kind", "pointer") &&
                 zv_str_is(pointer, "namespace",
                           VCS_PACKAGE_ATTEST_DHT_NAMESPACE) &&
                 zv_str_is(pointer, "semantic_root", package_hex) &&
                 transport &&
                 zv_str_is(pointer, "transport_root", transport));
        /* NOT the same window. The two kinds have different ceilings, and
         * a shared one is a real defect: a live seven-daemon flight caught
         * `offer` handing back a PROVIDER input whose 86400s window is over
         * the 7200s provider maximum, so an operator running exactly what
         * offer produced got the pointer published and the provider
         * refused — pointer-only, the silent no-op offer exists to
         * prevent. Each input must be publishable AS ITS OWN KIND. */
        ZV_CHECK("offer: each input's window is legal for its own record "
                 "kind, so running both actually publishes both",
                 provider && pointer &&
                 json_get_int(json_get(provider, "expiry")) -
                     json_get_int(json_get(provider, "not_before")) <=
                         (int64_t)VCS_ZCODE_DHT_PROVIDER_MAX_SECONDS &&
                 json_get_int(json_get(pointer, "expiry")) -
                     json_get_int(json_get(pointer, "not_before")) <=
                         (int64_t)VCS_ZCODE_DHT_POINTER_MAX_SECONDS);
        ZV_CHECK("offer: both windows are bounded and non-empty",
                 provider && pointer &&
                 json_get_int(json_get(provider, "expiry")) >
                     json_get_int(json_get(provider, "not_before")) &&
                 json_get_int(json_get(pointer, "expiry")) >
                     json_get_int(json_get(pointer, "not_before")));
        zv_cmd_free(&c);
    }

    /* (b) Idempotent: the transport root is a pure function of the exact
     * signed bytes, so offering twice yields the identical root. */
    {
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "attestation_id", id_hex);
        zcl_native_handle_zcode_package_attest_offer(&c.request, &c.reply);
        ZV_CHECK("offer: re-offering yields the identical transport root",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 first_transport_hex[0] &&
                 zv_str_is(&c.reply.data, "transport_root",
                           first_transport_hex));
        zv_cmd_free(&c);
    }

    /* (c) An id nothing is filed under names the missing prerequisite,
     * and does not crash. */
    {
        uint8_t ghost[32];
        zv_pattern_root(0x5c, ghost);
        char ghost_hex[65];
        zv_hex_enc(ghost, 32, ghost_hex);
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "attestation_id", ghost_hex);
        zcl_native_handle_zcode_package_attest_offer(&c.request, &c.reply);
        ZV_CHECK("offer: an unfiled id names ATTESTATION_ABSENT",
                 c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
                 strcmp(c.reply.error.code, "ATTESTATION_ABSENT") == 0 &&
                 strstr(c.reply.error.evidence,
                        vcs_package_attest_transport_result_string(
                            VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ABSENT)) != NULL);
        zv_cmd_free(&c);
    }

    /* (d) A malformed id is refused at normalize, by name, before any
     * store is opened. */
    {
        static const char *const bad[] = {
            "",                       /* absent */
            "deadbeef",               /* too short */
            "zz00000000000000000000000000000000000000000000000000000000000000",
            "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            struct zv_cmd c;
            zv_cmd_init(&c, datadir, "");
            if (bad[i][0])
                (void)json_push_kv_str(&c.input, "attestation_id", bad[i]);
            zcl_native_handle_zcode_package_attest_offer(&c.request,
                                                         &c.reply);
            char label[128];
            snprintf(label, sizeof(label),
                     "offer: malformed attestation_id [%zu] names "
                     "BAD_ATTESTATION_ID", i);
            ZV_CHECK(label,
                     c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
                     strcmp(c.reply.error.code, "BAD_ATTESTATION_ID") == 0 &&
                     c.reply.error.message[0] != '\0');
            zv_cmd_free(&c);
        }
    }

    test_rm_rf_recursive(datadir);
    return failures;
}

static int t_attest_pull(void)
{
    int failures = 0;
    char datadir[1024];
    test_make_tmpdir(datadir, sizeof(datadir), "zcode_verify", "attest-pull");
    char store[4400];
    snprintf(store, sizeof(store), "%s/zcode", datadir);

    uint8_t package_root[32], release_id[32], recipe_root[32];
    bool fixture = zv_publish_fixture(
        store,
        "#include \"add.h\"\nint add(int a, int b) { return a + b; }\n",
        "#include \"add.h\"\nint main(void) { return add(2, 3) == 5 ? 0 : 1; }\n",
        package_root, release_id, recipe_root);
    ZV_CHECK("pull: fixture store publishes", fixture);
    if (!fixture) {
        test_rm_rf_recursive(datadir);
        return failures + 1;
    }
    char package_hex[65];
    zv_hex_enc(package_root, 32, package_hex);
    /* Function-scoped so the stub's record text outlives the block that
     * builds it — the pointer set is read again by the later cases. */
    char records_one[1024];
    char records_all[2048];

    node_rpc_client_set_test_hook(zv_pull_rpc_hook);

    /* (a) Nobody has attested this package. That is NOT "the bytes could
     * not be reached", and the two must never collapse into one
     * not-found: the operator's next step differs completely — wait for a
     * verifier, versus fix reachability. */
    g_zv_pointer_records = "[]";
    {
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "package_root", package_hex);
        zcl_native_handle_zcode_package_attest_pull(&c.request, &c.reply);
        const struct json_value *rows = json_get(&c.reply.data, "rows");
        ZV_CHECK("pull: an empty pointer set is NO_ATTESTATION_POINTERS",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 zv_str_is(&c.reply.data, "status",
                           "NO_ATTESTATION_POINTERS") &&
                 zv_str_has(&c.reply.data, "blocker", "no_pointer_record") &&
                 json_get_int(json_get(&c.reply.data, "pointers_seen")) == 0 &&
                 json_get_int(json_get(&c.reply.data,
                                       "distinct_transport_roots")) == 0 &&
                 rows && rows->type == JSON_ARR && json_size(rows) == 0);
        ZV_CHECK("pull: the lookup asks the attestation pointer key",
                 g_zv_record_begin_calls > 0 && g_zv_pointer_query_exact);
        zv_cmd_free(&c);
    }

    /* Three blobs, one honest and two that must fail named rules:
     *   GOOD    a signed attestation of THIS package, bytes in the store
     *   FOREIGN a signed attestation of ANOTHER package, bytes in the
     *           store — the hostile pointer this namespace must survive
     *   ABSENT  a canonical root nothing is stored under
     * The two real ones are offered (so the bytes are reachable) and then
     * their attestations/ copies are removed, which is exactly the state
     * a receiving node is in before a pull. */
    char good_id[65] = "", good_transport[65] = "";
    char foreign_id[65] = "", foreign_transport[65] = "";
    bool offered = zv_offer_attestation(datadir, store,
                                        VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                                        package_root, release_id, recipe_root,
                                        0x22, true, good_id, good_transport);
    uint8_t foreign_pkg[32], foreign_rel[32], foreign_recipe[32];
    zv_pattern_root(0xa1, foreign_pkg);
    zv_pattern_root(0xa2, foreign_rel);
    zv_pattern_root(0xa3, foreign_recipe);
    offered = offered &&
        zv_offer_attestation(datadir, store,
                             VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, foreign_pkg,
                             foreign_rel, foreign_recipe, 0x33, true,
                             foreign_id, foreign_transport);
    ZV_CHECK("pull: two attestation blobs offered into the store", offered);
    if (!offered) {
        node_rpc_client_set_test_hook(NULL);
        test_rm_rf_recursive(datadir);
        return failures + 1;
    }
    uint8_t absent_root[32];
    zv_pattern_root(0xc7, absent_root);
    char absent_transport[65];
    zv_hex_enc(absent_root, 32, absent_transport);

    char good_path[4400], foreign_path[4400];
    snprintf(good_path, sizeof(good_path), "%s/attestations/%s", store,
             good_id);
    snprintf(foreign_path, sizeof(foreign_path), "%s/attestations/%s", store,
             foreign_id);

    /* (b) A pointer exists, nobody serves the bytes, and this node does
     * not already hold them. Distinct status, distinct blocker, and it is
     * NOT the empty-set status: "nobody has attested this" and "the bytes
     * are out of reach" send the operator to two different next steps. */
    {
        snprintf(records_one, sizeof(records_one),
                 "[{\"kind\":\"pointer\",\"transport_root\":\"%s\"}]",
                 absent_transport);
        g_zv_pointer_records = records_one;
        zcl_native_zcode_discovery_test_backend(zv_discover_no_provider,
                                                zv_route_attest_provider);
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "package_root", package_hex);
        zcl_native_handle_zcode_package_attest_pull(&c.request, &c.reply);
        const struct json_value *rows = json_get(&c.reply.data, "rows");
        const struct json_value *row = zv_row_for(rows, absent_transport);
        ZV_CHECK("pull: unreachable bytes are NOT reported as no pointers",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 zv_str_is(&c.reply.data, "status",
                           "ATTESTATION_BYTES_UNREACHABLE") &&
                 !zv_str_is(&c.reply.data, "status",
                            "NO_ATTESTATION_POINTERS") &&
                 zv_str_has(&c.reply.data, "blocker",
                            "no_authenticated_provider") &&
                 json_get_int(json_get(&c.reply.data, "pointers_seen")) == 1 &&
                 json_get_int(json_get(&c.reply.data, "fetched")) == 0 &&
                 json_get_int(json_get(&c.reply.data, "admitted")) == 0 &&
                 json_get_int(json_get(&c.reply.data, "refused")) == 1);
        ZV_CHECK("pull: the unreachable row names the discovery refusal",
                 row != NULL &&
                 zv_str_is(row, "fetch_outcome",
                           "PROVIDER_DISCOVERY_FAILED") &&
                 json_get(row, "fetched") &&
                 !json_get_bool(json_get(row, "fetched")) &&
                 !json_get_bool(json_get(row, "admitted")) &&
                 zv_str_has(row, "admit_result",
                            vcs_blob_result_string(VCS_BLOB_ERR_ABSENT)));
        zv_cmd_free(&c);
        zcl_native_zcode_discovery_test_backend(NULL, NULL);
    }
    /* Nothing was filed for a row whose bytes never arrived. */
    {
        struct stat st;
        ZV_CHECK("pull: an unreachable row files nothing",
                 stat(good_path, &st) != 0);
    }

    /* (c) THE case: one hostile pointer and one unreachable pointer in the
     * same set must not cost the honest verifier's attestation. All three
     * rows survive, each naming its own rule, and the good one lands
     * FILED. A sweep that aborted on the first failure would lose exactly
     * the evidence this command exists to collect. */
    {
        snprintf(records_all, sizeof(records_all),
                 "[{\"kind\":\"pointer\",\"transport_root\":\"%s\"},"
                 "{\"kind\":\"pointer\",\"transport_root\":\"%s\"},"
                 "{\"kind\":\"pointer\",\"transport_root\":\"%s\"},"
                 "{\"kind\":\"pointer\",\"transport_root\":\"%s\"}]",
                 foreign_transport, absent_transport, good_transport,
                 good_transport /* a republished duplicate */);
        g_zv_pointer_records = records_all;
        zcl_native_zcode_discovery_test_backend(zv_discover_attest_provider,
                                                zv_route_attest_provider);
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "package_root", package_hex);
        zcl_native_handle_zcode_package_attest_pull(&c.request, &c.reply);
        const struct json_value *rows = json_get(&c.reply.data, "rows");
        const struct json_value *good = zv_row_for(rows, good_transport);
        const struct json_value *foreign = zv_row_for(rows,
                                                      foreign_transport);
        const struct json_value *absent = zv_row_for(rows, absent_transport);

        ZV_CHECK("pull: one bad row does not abort the sweep — the good "
                 "attestation still lands filed",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 good != NULL &&
                 json_get_bool(json_get(good, "admitted")) &&
                 json_get_bool(json_get(good, "filed")) &&
                 zv_str_is(good, "attestation_id", good_id) &&
                 zv_str_is(good, "result_class", "test-pass") &&
                 zv_str_is(good, "admit_result",
                           "ok (blob=ok, attestation=ok)"));
        ZV_CHECK("pull: the hostile pointer is refused naming the binding "
                 "rule, and stays in the report",
                 foreign != NULL &&
                 !json_get_bool(json_get(foreign, "admitted")) &&
                 !json_get_bool(json_get(foreign, "filed")) &&
                 zv_str_has(foreign, "admit_result",
                            vcs_package_attest_transport_result_string(
                                VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BINDING)));
        ZV_CHECK("pull: a pointer to bytes this node does not hold names "
                 "the blob rule, not the fetch stub's optimism",
                 absent != NULL &&
                 json_get_bool(json_get(absent, "fetched")) &&
                 !json_get_bool(json_get(absent, "admitted")) &&
                 zv_str_has(absent, "admit_result",
                            vcs_package_attest_transport_result_string(
                                VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BLOB)) &&
                 zv_str_has(absent, "admit_result",
                            vcs_blob_result_string(VCS_BLOB_ERR_ABSENT)));
        ZV_CHECK("pull: every row carries a named admit_result",
                 rows && json_size(rows) == 3 &&
                 zv_str_has(json_at(rows, 0), "admit_result", "(blob=") &&
                 zv_str_has(json_at(rows, 1), "admit_result", "(blob=") &&
                 zv_str_has(json_at(rows, 2), "admit_result", "(blob="));

        /* Totals must be the rows, counted. A report whose headline
         * numbers disagree with its own rows is worse than no report. */
        int64_t admitted_rows = 0, filed_rows = 0, fetched_rows = 0;
        for (size_t i = 0; rows && i < json_size(rows); i++) {
            const struct json_value *row = json_at(rows, i);
            admitted_rows += json_get_bool(json_get(row, "admitted")) ? 1 : 0;
            filed_rows += json_get_bool(json_get(row, "filed")) ? 1 : 0;
            fetched_rows += json_get_bool(json_get(row, "fetched")) ? 1 : 0;
        }
        ZV_CHECK("pull: totals are internally consistent with the rows",
                 json_get_int(json_get(&c.reply.data, "pointers_seen")) == 4 &&
                 json_get_int(json_get(&c.reply.data,
                                       "distinct_transport_roots")) == 3 &&
                 json_get_int(json_get(&c.reply.data, "admitted")) ==
                     admitted_rows &&
                 json_get_int(json_get(&c.reply.data, "filed")) ==
                     filed_rows &&
                 json_get_int(json_get(&c.reply.data, "fetched")) ==
                     fetched_rows &&
                 json_get_int(json_get(&c.reply.data, "admitted")) == 1 &&
                 json_get_int(json_get(&c.reply.data, "refused")) == 2 &&
                 json_get_int(json_get(&c.reply.data, "admitted")) +
                     json_get_int(json_get(&c.reply.data, "refused")) ==
                     json_get_int(json_get(&c.reply.data,
                                           "distinct_transport_roots")) &&
                 !json_get_bool(json_get(&c.reply.data, "rows_truncated")));
        ZV_CHECK("pull: admitted evidence sets the admitted status",
                 zv_str_is(&c.reply.data, "status", "ATTESTATIONS_ADMITTED") &&
                 json_get(&c.reply.data, "blocker") == NULL);
        zv_cmd_free(&c);
        zcl_native_zcode_discovery_test_backend(NULL, NULL);
    }

    /* The filesystem agrees with the report: the honest attestation is
     * filed, and the one that failed the binding check is not. Refusing
     * BEFORE filing is the whole security property on this path. */
    {
        struct stat st;
        ZV_CHECK("pull: the admitted attestation is on disk",
                 stat(good_path, &st) == 0 && st.st_size > 0);
        ZV_CHECK("pull: the binding-mismatched attestation is NOT on disk",
                 stat(foreign_path, &st) != 0);
    }

    /* (d) Re-pulling the same set is idempotent: already_present, not
     * re-filed, and the totals still add up. */
    {
        zcl_native_zcode_discovery_test_backend(zv_discover_attest_provider,
                                                zv_route_attest_provider);
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "package_root", package_hex);
        zcl_native_handle_zcode_package_attest_pull(&c.request, &c.reply);
        const struct json_value *good =
            zv_row_for(json_get(&c.reply.data, "rows"), good_transport);
        ZV_CHECK("pull: re-pulling an already-filed attestation is "
                 "idempotent",
                 good != NULL &&
                 json_get_bool(json_get(good, "admitted")) &&
                 !json_get_bool(json_get(good, "filed")) &&
                 json_get_bool(json_get(good, "already_present")) &&
                 json_get_int(json_get(&c.reply.data, "filed")) == 0 &&
                 json_get_int(json_get(&c.reply.data, "admitted")) == 1);
        zv_cmd_free(&c);
        zcl_native_zcode_discovery_test_backend(NULL, NULL);
    }

    /* (d2) The status ladder must not contradict its own totals.
     * Admission is deliberately unconditional, so a blob this node
     * ALREADY HOLDS is admitted and filed even when provider discovery
     * serves nothing. A ladder that tested fetched before admitted
     * printed ATTESTATION_BYTES_UNREACHABLE — "no authenticated provider
     * served the attestation bytes" — in the same reply that reported
     * filed=1, sending an operator to repair reachability that was never
     * broken. The evidence landed; the status has to say so. */
    {
        char held_id[65] = "", held_transport[65] = "";
        bool held = zv_offer_attestation(
            datadir, store, VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, package_root,
            release_id, recipe_root, 0x44, true, held_id, held_transport);
        ZV_CHECK("pull: a third attestation is offered but not yet filed",
                 held);
        char held_path[4400];
        snprintf(held_path, sizeof(held_path), "%s/attestations/%s", store,
                 held_id);
        char records_held[1024];
        snprintf(records_held, sizeof(records_held),
                 "[{\"kind\":\"pointer\",\"transport_root\":\"%s\"}]",
                 held_transport);
        const char *saved_records = g_zv_pointer_records;
        g_zv_pointer_records = records_held;
        /* Discovery fails. The bytes are here anyway. */
        zcl_native_zcode_discovery_test_backend(zv_discover_no_provider,
                                                zv_route_attest_provider);
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "package_root", package_hex);
        zcl_native_handle_zcode_package_attest_pull(&c.request, &c.reply);
        ZV_CHECK("pull: an attestation admitted from bytes already held is "
                 "NOT reported as unreachable",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 zv_str_is(&c.reply.data, "status", "ATTESTATIONS_ADMITTED") &&
                 !zv_str_is(&c.reply.data, "status",
                            "ATTESTATION_BYTES_UNREACHABLE"));
        ZV_CHECK("pull: no blocker is named when evidence actually landed",
                 json_get(&c.reply.data, "blocker") == NULL);
        ZV_CHECK("pull: the totals that contradicted the old status are the "
                 "ones asserted here",
                 json_get_int(json_get(&c.reply.data, "fetched")) == 0 &&
                 json_get_int(json_get(&c.reply.data, "admitted")) == 1 &&
                 json_get_int(json_get(&c.reply.data, "filed")) == 1 &&
                 json_get_int(json_get(&c.reply.data, "refused")) == 0);
        struct stat st;
        ZV_CHECK("pull: the already-held attestation is on disk", held &&
                 stat(held_path, &st) == 0 && st.st_size > 0);
        zv_cmd_free(&c);
        zcl_native_zcode_discovery_test_backend(NULL, NULL);
        g_zv_pointer_records = saved_records;
    }

    /* (e) The row cap is reported honestly rather than truncating in
     * silence, and it bounds the rows actually produced. */
    {
        zcl_native_zcode_discovery_test_backend(zv_discover_attest_provider,
                                                zv_route_attest_provider);
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "package_root", package_hex);
        (void)json_push_kv_int(&c.input, "maximum_records", 1);
        zcl_native_handle_zcode_package_attest_pull(&c.request, &c.reply);
        const struct json_value *rows = json_get(&c.reply.data, "rows");
        ZV_CHECK("pull: rows_truncated is honest at the cap",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 json_get_bool(json_get(&c.reply.data, "rows_truncated")) &&
                 json_get_int(json_get(&c.reply.data, "maximum_records")) ==
                     1 &&
                 json_get_int(json_get(&c.reply.data,
                                       "distinct_transport_roots")) == 1 &&
                 rows && json_size(rows) == 1 &&
                 json_get_int(json_get(&c.reply.data, "pointers_seen")) == 4);
        zv_cmd_free(&c);
        zcl_native_zcode_discovery_test_backend(NULL, NULL);
    }

    /* (f) Bad inputs are refused at normalize, by name. */
    {
        struct zv_cmd c;
        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "package_root", "not-a-root");
        zcl_native_handle_zcode_package_attest_pull(&c.request, &c.reply);
        ZV_CHECK("pull: a malformed package_root names BAD_PACKAGE_ROOT",
                 c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
                 strcmp(c.reply.error.code, "BAD_PACKAGE_ROOT") == 0);
        zv_cmd_free(&c);

        zv_cmd_init(&c, datadir, "");
        (void)json_push_kv_str(&c.input, "package_root", package_hex);
        (void)json_push_kv_int(&c.input, "maximum_records", 0);
        zcl_native_handle_zcode_package_attest_pull(&c.request, &c.reply);
        ZV_CHECK("pull: maximum_records=0 names BAD_MAXIMUM_RECORDS",
                 c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
                 strcmp(c.reply.error.code, "BAD_MAXIMUM_RECORDS") == 0);
        zv_cmd_free(&c);
    }

    node_rpc_client_set_test_hook(NULL);
    g_zv_pointer_records = "[]";
    test_rm_rf_recursive(datadir);
    return failures;
}

/* ── 3e. the attestation POINTER publish gate ──────────────────────────
 * boot_zcode_dht_attestation_pointer_publish_gate stops THIS node from
 * advertising an attestation pointer it cannot stand behind. Every
 * refusal below is reached by construction and asserted by its named
 * code plus the exact transport rule — "it refused" would pass when the
 * gate refuses for the wrong reason, which is how a fail-closed design
 * rots into a fail-random one.
 *
 * This case owns process-global state (the -packagehost flags, the
 * datadir, and the node-global package store), so it opens them on a
 * ./test-tmp tree and restores all three before returning. */

static void zv_gate_spec(struct vcs_zcode_dht_publish_spec *spec,
                         const uint8_t semantic_root[32],
                         const uint8_t transport_root[32])
{
    memset(spec, 0, sizeof(*spec));
    spec->kind = VCS_ZCODE_DHT_RECORD_POINTER;
    snprintf(spec->namespace_name, sizeof(spec->namespace_name), "%s",
             VCS_PACKAGE_ATTEST_DHT_NAMESPACE);
    memcpy(spec->semantic_root, semantic_root, 32);
    memcpy(spec->transport_root, transport_root, 32);
    spec->sequence = 1;
    spec->not_before = 1000;
    spec->expiry = 1000 + 86400;
}

/* Signed attestation bytes for one package, plus the id and blob root
 * they hash to. Nothing is stored. */
static bool zv_gate_wire(uint8_t cls, const uint8_t package_root[32],
                         uint8_t signer_seed, uint8_t **wire_out,
                         size_t *wire_len_out, uint8_t id_out[32],
                         uint8_t transport_root_out[32])
{
    uint8_t release_id[32], recipe_root[32];
    zv_pattern_root((uint8_t)(signer_seed + 1u), release_id);
    zv_pattern_root((uint8_t)(signer_seed + 2u), recipe_root);
    struct vcs_package_attest a;
    if (!zv_attest(&a, cls, package_root, release_id, recipe_root,
                   signer_seed))
        return false;
    if (vcs_package_attest_id(&a, id_out) != VCS_PACKAGE_ATTEST_OK)
        return false;
    *wire_out = NULL;
    *wire_len_out = 0;
    if (vcs_package_attest_serialize(&a, wire_out, wire_len_out) !=
        VCS_PACKAGE_ATTEST_OK)
        return false;
    if (!vcs_blob_root(*wire_out, *wire_len_out, transport_root_out)) {
        free(*wire_out);
        *wire_out = NULL;
        return false;
    }
    return true;
}

static bool zv_gate_refused(struct json_value *result, const char *code,
                            const char *rule)
{
    return json_get(result, "ok") && !json_get_bool(json_get(result, "ok")) &&
           zv_str_is(result, "code", code) &&
           zv_str_has(result, "message", rule);
}

static int t_attest_publish_gate(void)
{
    int failures = 0;
    uint8_t package_root[32], other_root[32];
    zv_pattern_root(0x31, package_root);
    zv_pattern_root(0x71, other_root);

    /* (a) No package store at all: the prerequisite is named, and the
     * gate never dereferences one. */
    vcs_package_store_close_global();
    {
        uint8_t bogus[32];
        zv_pattern_root(0x0d, bogus);
        struct vcs_zcode_dht_publish_spec spec;
        zv_gate_spec(&spec, package_root, bogus);
        struct json_value result;
        json_init(&result);
        bool allowed =
            boot_zcode_dht_attestation_pointer_publish_gate(&spec, &result);
        ZV_CHECK("gate: no package store names NO_PACKAGE_STORE",
                 !allowed &&
                 json_get(&result, "ok") &&
                 !json_get_bool(json_get(&result, "ok")) &&
                 zv_str_is(&result, "code", "NO_PACKAGE_STORE"));
        ZV_CHECK("gate: no package store names z23 join, not flags",
                 zv_str_has(&result, "message", "z23 join") &&
                 !zv_str_has(&result, "message", "-packagehost") &&
                 !zv_str_has(&result, "message", "-buildworker"));
        json_free(&result);
        json_init(&result);
        allowed = boot_zcode_dht_package_pointer_publish_gate(&spec, &result);
        ZV_CHECK("gate: package pointer with no store names z23 join",
                 !allowed &&
                 zv_str_is(&result, "code", "NO_PACKAGE_STORE") &&
                 zv_str_has(&result, "message", "z23 join") &&
                 !zv_str_has(&result, "message", "-packagehost") &&
                 !zv_str_has(&result, "message", "-buildworker"));
        json_free(&result);
    }

    const char *argv[] = { "zclassic23-test", "-packagehost=1",
                           "-packagequota=100000000" };
    ParseParameters(3, argv);
    char dd[1024];
    test_make_tmpdir(dd, sizeof(dd), "zcode_verify", "attest-gate");
    SetDataDir(dd);
    bool opened = vcs_package_store_open_global() &&
                  vcs_package_store_global() != NULL;
    ZV_CHECK("gate: node-global package store opens on the temp datadir",
             opened);
    if (!opened) {
        vcs_package_store_close_global();
        const char *reset[] = { "zclassic23-test" };
        ParseParameters(1, reset);
        SetDataDir("");
        test_rm_rf_recursive(dd);
        return failures + 1;
    }
    struct vcs_package_store *store = vcs_package_store_global();
    const char *zcode_dir = vcs_package_store_root_dir(store);

    /* (b) A pointer to bytes this node does not hold. */
    {
        uint8_t missing[32];
        zv_pattern_root(0x4e, missing);
        struct vcs_zcode_dht_publish_spec spec;
        zv_gate_spec(&spec, package_root, missing);
        struct json_value result;
        json_init(&result);
        bool allowed =
            boot_zcode_dht_attestation_pointer_publish_gate(&spec, &result);
        ZV_CHECK("gate: unheld bytes name ATTESTATION_NOT_HELD",
                 !allowed &&
                 zv_gate_refused(&result, "ATTESTATION_NOT_HELD",
                                 vcs_blob_result_string(VCS_BLOB_ERR_ABSENT)));
        json_free(&result);
    }

    /* (c) Bytes this node DOES hold that are not an attestation at all.
     * Possession is not evidence. */
    {
        static const uint8_t junk[96] = { 0x6e, 0x6f, 0x74, 0x2d, 0x61,
                                          0x2d, 0x77, 0x69, 0x72, 0x65 };
        uint8_t junk_root[32] = { 0 };
        bool put = vcs_blob_put_to(store, junk, sizeof(junk), junk_root) ==
                   VCS_BLOB_OK;
        struct vcs_zcode_dht_publish_spec spec;
        zv_gate_spec(&spec, package_root, junk_root);
        struct json_value result;
        json_init(&result);
        bool allowed =
            put && boot_zcode_dht_attestation_pointer_publish_gate(&spec,
                                                                   &result);
        ZV_CHECK("gate: held non-attestation bytes name ATTESTATION_INVALID",
                 put && !allowed &&
                 zv_gate_refused(&result, "ATTESTATION_INVALID",
                                 vcs_package_attest_transport_result_string(
                                     VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ATTEST)));
        json_free(&result);
    }

    /* (d) THE one that matters: a valid, held attestation whose
     * package_root is NOT the pointer's semantic_root. The pointer would
     * be advertising evidence about a package the wire never mentions. It
     * must be refused, and — because the binding is checked BEFORE the
     * filer runs — nothing may be written. */
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t attest_id[32], transport_root[32];
    bool built = zv_gate_wire(VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                              package_root, 0x22, &wire, &wire_len, attest_id,
                              transport_root);
    bool stored = built && vcs_blob_put_to(store, wire, wire_len, NULL) ==
                               VCS_BLOB_OK;
    free(wire);
    ZV_CHECK("gate: a signed attestation blob is held by this node",
             built && stored);
    char attest_path[4400] = "";
    if (built) {
        char id_hex[65];
        zv_hex_enc(attest_id, 32, id_hex);
        snprintf(attest_path, sizeof(attest_path), "%s/attestations/%s",
                 zcode_dir, id_hex);
    }
    if (stored) {
        struct vcs_zcode_dht_publish_spec spec;
        zv_gate_spec(&spec, other_root, transport_root);
        struct json_value result;
        json_init(&result);
        bool allowed =
            boot_zcode_dht_attestation_pointer_publish_gate(&spec, &result);
        struct stat st;
        ZV_CHECK("gate: a pointer whose semantic_root is not the "
                 "attestation's package_root names "
                 "ATTESTATION_BINDING_MISMATCH",
                 !allowed &&
                 zv_gate_refused(&result, "ATTESTATION_BINDING_MISMATCH",
                                 vcs_package_attest_transport_result_string(
                                     VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BINDING)));
        ZV_CHECK("gate: a binding mismatch files nothing",
                 stat(attest_path, &st) != 0);
        json_free(&result);
    }

    /* (e) The happy path: held, valid, correctly bound. It passes, and —
     * as the header documents — it FILES the attestation even on a plan,
     * because _admit() is the single filer. */
    if (stored) {
        struct vcs_zcode_dht_publish_spec spec;
        zv_gate_spec(&spec, package_root, transport_root);
        struct json_value result;
        json_init(&result);
        bool allowed =
            boot_zcode_dht_attestation_pointer_publish_gate(&spec, &result);
        struct stat st;
        ZV_CHECK("gate: a held, valid, correctly-bound attestation passes",
                 allowed);
        ZV_CHECK("gate: passing files the attestation locally (documented, "
                 "not read-only)",
                 stat(attest_path, &st) == 0 &&
                 (size_t)st.st_size == wire_len);
        json_free(&result);

        json_init(&result);
        bool again =
            boot_zcode_dht_attestation_pointer_publish_gate(&spec, &result);
        ZV_CHECK("gate: re-running the same publish is idempotent", again);
        json_free(&result);
    }

    /* (f) A different object already occupying the attestation id. The id
     * IS the content hash, so this is impossible for honest wires and
     * fails closed rather than overwriting. */
    {
        uint8_t *w2 = NULL;
        size_t w2_len = 0;
        uint8_t id2[32], root2[32];
        bool b2 = zv_gate_wire(VCS_PACKAGE_ATTEST_RESULT_TEST_PASS,
                               package_root, 0x33, &w2, &w2_len, id2, root2);
        bool s2 = b2 && vcs_blob_put_to(store, w2, w2_len, NULL) ==
                            VCS_BLOB_OK;
        free(w2);
        char id2_hex[65] = "", path2[4400] = "";
        if (b2) {
            zv_hex_enc(id2, 32, id2_hex);
            snprintf(path2, sizeof(path2), "%s/attestations/%s", zcode_dir,
                     id2_hex);
        }
        static const char squatter[] = "not the attestation these bytes are";
        bool squatted = s2 &&
            zv_write_file(path2, squatter, sizeof(squatter) - 1, 0600);
        struct vcs_zcode_dht_publish_spec spec;
        memset(&spec, 0, sizeof(spec));
        if (b2)
            zv_gate_spec(&spec, package_root, root2);
        struct json_value result;
        json_init(&result);
        bool allowed = squatted &&
            boot_zcode_dht_attestation_pointer_publish_gate(&spec, &result);
        ZV_CHECK("gate: a squatted attestation id names "
                 "ATTESTATION_STORE_CONFLICT",
                 squatted && !allowed &&
                 zv_gate_refused(&result, "ATTESTATION_STORE_CONFLICT",
                                 vcs_package_attest_transport_result_string(
                                     VCS_PACKAGE_ATTEST_TRANSPORT_ERR_CONFLICT)));
        json_free(&result);
    }

    /* Restore the process globals this case borrowed. */
    vcs_package_store_close_global();
    ZV_CHECK("gate: the node-global store is closed again",
             vcs_package_store_global() == NULL);
    const char *reset[] = { "zclassic23-test" };
    ParseParameters(1, reset);
    SetDataDir("");
    test_rm_rf_recursive(dd);
    return failures;
}

/* boot_zcode_dht_work_pointer_publish_gate stops THIS node from
 * advertising a work-solution pointer it cannot stand behind. The arms
 * this suite can reach without the full accepted-work chain fixture are
 * the store and shape arms; the binding arms (a real package proving a
 * different task) belong to vcs_zcode_work_solution_admit and are proven
 * against a real reconstructed chain by the dev-objects suite — the gate
 * delegates to that one call, so its mapping of TASK_MISMATCH is the only
 * uncovered line and is a four-line if. Owns the same process globals the
 * attestation gate case does; same open/restore discipline. */
static void zv_work_gate_spec(struct vcs_zcode_dht_publish_spec *spec,
                              const uint8_t semantic_root[32],
                              const uint8_t transport_root[32])
{
    memset(spec, 0, sizeof(*spec));
    spec->kind = VCS_ZCODE_DHT_RECORD_POINTER;
    snprintf(spec->namespace_name, sizeof(spec->namespace_name), "%s",
             VCS_ZCODE_WORK_DHT_NAMESPACE);
    memcpy(spec->semantic_root, semantic_root, 32);
    memcpy(spec->transport_root, transport_root, 32);
    spec->sequence = 1;
    spec->not_before = 1000;
    spec->expiry = 1000 + 86400;
}

static int t_work_publish_gate(void)
{
    int failures = 0;
    uint8_t task_root[32], transport_root[32];
    zv_pattern_root(0x51, task_root);
    zv_pattern_root(0x52, transport_root);

    /* (a) No package store at all. */
    vcs_package_store_close_global();
    {
        struct vcs_zcode_dht_publish_spec spec;
        zv_work_gate_spec(&spec, task_root, transport_root);
        struct json_value result;
        json_init(&result);
        bool allowed =
            boot_zcode_dht_work_pointer_publish_gate(&spec, &result);
        ZV_CHECK("work gate: no package store names NO_PACKAGE_STORE",
                 !allowed &&
                 zv_str_is(&result, "code", "NO_PACKAGE_STORE"));
        json_free(&result);
    }

    const char *argv[] = { "zclassic23-test", "-packagehost=1",
                           "-packagequota=100000000" };
    ParseParameters(3, argv);
    char dd[1024];
    test_make_tmpdir(dd, sizeof(dd), "zcode_verify", "work-gate");
    SetDataDir(dd);
    bool opened = vcs_package_store_open_global() &&
                  vcs_package_store_global() != NULL;
    ZV_CHECK("work gate: node-global package store opens on the temp"
             " datadir",
             opened);
    if (!opened) {
        vcs_package_store_close_global();
        const char *reset[] = { "zclassic23-test" };
        ParseParameters(1, reset);
        SetDataDir("");
        test_rm_rf_recursive(dd);
        return failures + 1;
    }
    struct vcs_package_store *store = vcs_package_store_global();

    /* (b) A package root this node does not hold at all. */
    {
        struct vcs_zcode_dht_publish_spec spec;
        zv_work_gate_spec(&spec, task_root, transport_root);
        struct json_value result;
        json_init(&result);
        bool allowed =
            boot_zcode_dht_work_pointer_publish_gate(&spec, &result);
        ZV_CHECK("work gate: an unheld package names"
                 " WORK_NOT_RECONSTRUCTIBLE",
                 !allowed &&
                 zv_str_is(&result, "code", "WORK_NOT_RECONSTRUCTIBLE"));
        json_free(&result);
    }

    /* (c) Bytes this node DOES hold that are not a source package.
     * Possession is not a solution: the blob root reconstructs to
     * nothing. */
    {
        static const uint8_t junk[96] = { 0x6e, 0x6f, 0x74, 0x2d, 0x61,
                                          0x2d, 0x63, 0x61, 0x72, 0x72,
                                          0x69, 0x65, 0x72 };
        uint8_t junk_root[32] = { 0 };
        bool put = vcs_blob_put_to(store, junk, sizeof(junk), junk_root) ==
                   VCS_BLOB_OK;
        struct vcs_zcode_dht_publish_spec spec;
        zv_work_gate_spec(&spec, task_root, junk_root);
        struct json_value result;
        json_init(&result);
        bool allowed =
            put && boot_zcode_dht_work_pointer_publish_gate(&spec, &result);
        ZV_CHECK("work gate: held non-package bytes name"
                 " WORK_NOT_RECONSTRUCTIBLE",
                 put && !allowed &&
                 zv_str_is(&result, "code", "WORK_NOT_RECONSTRUCTIBLE"));
        json_free(&result);
    }

    /* Restore the process globals this case borrowed. */
    vcs_package_store_close_global();
    const char *reset[] = { "zclassic23-test" };
    ParseParameters(1, reset);
    SetDataDir("");
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 4. end-to-end external verifier ────────────────────────────────── */

/* boot_zcode_dht_task_pointer_publish_gate stops THIS node from
 * advertising a task posting it cannot stand behind. Unlike the work gate
 * (whose binding arm needs the full accepted-work fixture), every arm is
 * reachable here: building one real carrier is three small wires. Owns
 * the same process globals the work gate case does; same open/restore
 * discipline. */
static void zv_task_gate_spec(struct vcs_zcode_dht_publish_spec *spec,
                              const uint8_t semantic_root[32],
                              const uint8_t transport_root[32])
{
    memset(spec, 0, sizeof(*spec));
    spec->kind = VCS_ZCODE_DHT_RECORD_POINTER;
    snprintf(spec->namespace_name, sizeof(spec->namespace_name), "%s",
             VCS_ZCODE_TASK_DHT_NAMESPACE);
    memcpy(spec->semantic_root, semantic_root, 32);
    memcpy(spec->transport_root, transport_root, 32);
    spec->sequence = 1;
    spec->not_before = 1000;
    spec->expiry = 1000 + 86400;
}

/* One real carrier exported into `store`: a valid policy, a task whose
 * goal_root commits the goal text, live (or already expired) at gate
 * time. Fills task_root/context_root and returns the export result. */
static enum vcs_zcode_task_context_error zv_export_task_context(
    struct vcs_package_store *store, int64_t expires_unix,
    uint8_t task_root[32], uint8_t context_root[32])
{
    struct vcs_zcode_proof_policy_v1 policy;
    memset(&policy, 0, sizeof(policy));
    policy.schema_version = VCS_ZCODE_DEV_VERSION;
    policy.required_proofs = VCS_ZCODE_PROOF_COMPILE |
                             VCS_ZCODE_PROOF_TEST | VCS_ZCODE_PROOF_FUZZ |
                             VCS_ZCODE_PROOF_REVIEW |
                             VCS_ZCODE_PROOF_LOCAL_REPRODUCTION;
    policy.minimum_compile_receipts = 2;
    policy.minimum_test_receipts = 2;
    policy.minimum_fuzz_receipts = 1;
    policy.minimum_reviews = 1;
    policy.minimum_matching_receipts = 2;
    policy.flags = VCS_ZCODE_POLICY_INDEPENDENT_SIGNERS |
                   VCS_ZCODE_POLICY_RELEASE_BYTE_IDENTITY;
    policy.deterministic_fuzz_seeds = 64;
    policy.audit_basis_points = 100;
    policy.maximum_proof_age_seconds = 3600;
    uint8_t policy_root[32];
    if (vcs_zcode_proof_policy_root(&policy, policy_root) !=
        VCS_ZCODE_DEV_OK)
        return VCS_ZCODE_TASK_CONTEXT_POLICY_WIRE;
    uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
    if (vcs_zcode_proof_policy_serialize(&policy, policy_wire) !=
        VCS_ZCODE_DEV_OK)
        return VCS_ZCODE_TASK_CONTEXT_POLICY_WIRE;

    static const char goal[] = "post me: one task, three wires, one root";
    struct vcs_zcode_task_v1 task;
    memset(&task, 0, sizeof(task));
    task.schema_version = VCS_ZCODE_DEV_VERSION;
    /* Validation refuses zero roots, so every unconstrained root gets a
     * distinct nonzero pattern. */
    memset(task.source_root, 0x21, 32);
    memset(task.dependency_lock_root, 0x22, 32);
    memset(task.toolchain_capsule_root, 0x23, 32);
    memset(task.write_scope_root, 0x24, 32);
    memset(task.acceptance_tests_root, 0x25, 32);
    memset(task.model_policy_root, 0x26, 32);
    memcpy(task.proof_policy_root, policy_root, 32);
    sha3_256((const uint8_t *)goal, sizeof(goal) - 1u, task.goal_root);
    task.capabilities = VCS_ZCODE_TASK_CAP_V1_MASK;
    task.max_changed_files = 32;
    task.max_patch_bytes = 1024 * 1024;
    task.max_context_bytes = 2 * 1024 * 1024;
    task.max_cpu_seconds = 120;
    task.max_memory_bytes = UINT64_C(512) * 1024 * 1024;
    task.max_output_bytes = UINT64_C(64) * 1024 * 1024;
    task.expires_unix = expires_unix;
    uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
    if (vcs_zcode_task_serialize(&task, task_wire) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(&task, task_root) != VCS_ZCODE_DEV_OK)
        return VCS_ZCODE_TASK_CONTEXT_TASK_WIRE;
    /* Export while the task is live (yesterday's clock) so an
     * already-expired posting can still enter the store — exactly how a
     * live posting looks after a week. */
    return vcs_zcode_task_context_export(
        task_wire, sizeof(task_wire), (const uint8_t *)goal,
        sizeof(goal) - 1u, policy_wire, sizeof(policy_wire), store,
        expires_unix - 86400, context_root);
}

static int t_task_publish_gate(void)
{
    int failures = 0;
    uint8_t task_root[32], transport_root[32];
    zv_pattern_root(0x61, task_root);
    zv_pattern_root(0x62, transport_root);

    /* (a) No package store at all. */
    vcs_package_store_close_global();
    {
        struct vcs_zcode_dht_publish_spec spec;
        zv_task_gate_spec(&spec, task_root, transport_root);
        struct json_value result;
        json_init(&result);
        bool allowed =
            boot_zcode_dht_task_pointer_publish_gate(&spec, &result);
        ZV_CHECK("task gate: no package store names NO_PACKAGE_STORE",
                 !allowed &&
                 zv_str_is(&result, "code", "NO_PACKAGE_STORE"));
        json_free(&result);
    }

    const char *argv[] = { "zclassic23-test", "-packagehost=1",
                           "-packagequota=100000000" };
    ParseParameters(3, argv);
    char dd[1024];
    test_make_tmpdir(dd, sizeof(dd), "zcode_verify", "task-gate");
    SetDataDir(dd);
    bool opened = vcs_package_store_open_global() &&
                  vcs_package_store_global() != NULL;
    ZV_CHECK("task gate: node-global package store opens on the temp"
             " datadir",
             opened);
    if (!opened) {
        vcs_package_store_close_global();
        const char *reset[] = { "zclassic23-test" };
        ParseParameters(1, reset);
        SetDataDir("");
        test_rm_rf_recursive(dd);
        return failures + 1;
    }
    struct vcs_package_store *store = vcs_package_store_global();
    int64_t now = (int64_t)platform_time_wall_unix();

    /* (b) A context root this node does not hold at all. */
    {
        struct vcs_zcode_dht_publish_spec spec;
        zv_task_gate_spec(&spec, task_root, transport_root);
        struct json_value result;
        json_init(&result);
        bool allowed =
            boot_zcode_dht_task_pointer_publish_gate(&spec, &result);
        ZV_CHECK("task gate: an unheld context names"
                 " TASK_CONTEXT_NOT_VERIFIABLE",
                 !allowed &&
                 zv_str_is(&result, "code",
                           "TASK_CONTEXT_NOT_VERIFIABLE"));
        json_free(&result);
    }

    /* (c) Held bytes that are not the fixed carrier. */
    {
        static const uint8_t junk[48] = "not-a-task-context-carrier-at-all";
        uint8_t junk_root[32] = { 0 };
        bool put = vcs_blob_put_to(store, junk, sizeof(junk), junk_root) ==
                   VCS_BLOB_OK;
        struct vcs_zcode_dht_publish_spec spec;
        zv_task_gate_spec(&spec, task_root, junk_root);
        struct json_value result;
        json_init(&result);
        bool allowed =
            put && boot_zcode_dht_task_pointer_publish_gate(&spec, &result);
        ZV_CHECK("task gate: held non-carrier bytes name"
                 " TASK_CONTEXT_NOT_VERIFIABLE",
                 put && !allowed &&
                 zv_str_is(&result, "code",
                           "TASK_CONTEXT_NOT_VERIFIABLE"));
        json_free(&result);
    }

    /* (d) A REAL live posting whose context proves exactly the pointer's
     * task root: the only arm that may pass. */
    {
        uint8_t live_task[32], live_context[32];
        enum vcs_zcode_task_context_error exported = zv_export_task_context(
            store, now + 86400, live_task, live_context);
        struct vcs_zcode_dht_publish_spec spec;
        zv_task_gate_spec(&spec, live_task, live_context);
        struct json_value result;
        json_init(&result);
        bool allowed = exported == VCS_ZCODE_TASK_CONTEXT_OK &&
                       boot_zcode_dht_task_pointer_publish_gate(&spec,
                                                                &result);
        ZV_CHECK("task gate: a live context proving the pointer's task"
                 " root is publishable",
                 exported == VCS_ZCODE_TASK_CONTEXT_OK && allowed);
        json_free(&result);

        spec.expiry = (uint64_t)now + 86401u;
        json_init(&result);
        allowed = boot_zcode_dht_task_pointer_publish_gate(&spec, &result);
        ZV_CHECK("task gate: a pointer cannot outlive its task",
                 !allowed &&
                 zv_str_is(&result, "code",
                           "TASK_POINTER_OUTLIVES_TASK"));
        json_free(&result);

        /* (e) The same context behind a pointer naming a DIFFERENT task:
         * the binding refusal. */
        uint8_t flipped[32];
        memcpy(flipped, live_task, 32);
        flipped[0] ^= 1u;
        zv_task_gate_spec(&spec, flipped, live_context);
        json_init(&result);
        allowed = boot_zcode_dht_task_pointer_publish_gate(&spec, &result);
        ZV_CHECK("task gate: a context proving a different task names"
                 " TASK_ROOT_NOT_BOUND",
                 !allowed &&
                 zv_str_is(&result, "code", "TASK_ROOT_NOT_BOUND"));
        json_free(&result);
    }

    /* (f) A posting that was live when exported but has since expired:
     * the gate re-checks liveness at publish time, so it refuses here
     * exactly as it refuses at every puller. */
    {
        uint8_t stale_task[32], stale_context[32];
        enum vcs_zcode_task_context_error exported = zv_export_task_context(
            store, now - 60, stale_task, stale_context);
        struct vcs_zcode_dht_publish_spec spec;
        zv_task_gate_spec(&spec, stale_task, stale_context);
        struct json_value result;
        json_init(&result);
        bool allowed = exported == VCS_ZCODE_TASK_CONTEXT_OK &&
                       boot_zcode_dht_task_pointer_publish_gate(&spec,
                                                                &result);
        ZV_CHECK("task gate: an expired posting names"
                 " TASK_CONTEXT_NOT_VERIFIABLE",
                 exported == VCS_ZCODE_TASK_CONTEXT_OK && !allowed &&
                 zv_str_is(&result, "code",
                           "TASK_CONTEXT_NOT_VERIFIABLE"));
        json_free(&result);
    }

    /* Restore the process globals this case borrowed. */
    vcs_package_store_close_global();
    const char *reset[] = { "zclassic23-test" };
    ParseParameters(1, reset);
    SetDataDir("");
    test_rm_rf_recursive(dd);
    return failures;
}



static bool zv_dir_is_empty(const char *path)
{
    DIR *d = opendir(path);
    if (!d)
        return false;
    bool empty = true;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
            empty = false;
            break;
        }
    }
    closedir(d);
    return empty;
}

/* Run the verifier binary against a fixture store; returns the spawn exit
 * code and fills the captured stdout. */
static int zv_run_verifier(const char *root_hex, const char *store,
                           const char *key_path, const char *work,
                           char *buf, size_t cap)
{
    char store_arg[4400];
    char key_arg[4400];
    char work_arg[4400];
    snprintf(store_arg, sizeof(store_arg), "--store=%s", store);
    snprintf(key_arg, sizeof(key_arg), "--key=%s", key_path);
    snprintf(work_arg, sizeof(work_arg), "--work=%s", work);
    const char *argv[] = { ZV_VERIFIER_BIN, root_hex, store_arg, key_arg,
                           work_arg, NULL };
    return zcl_spawn_capture(argv, buf, cap, 300000);
}

/* Run the verifier binary in EMIT (install-build) mode against a fixture
 * store; reproduce_against (nullable) arms the third-party byte-identity
 * check against a reference build-report. Returns the spawn exit code and
 * fills the captured stdout (stderr is not captured). */
static int zv_run_emit(const char *root_hex, const char *store,
                       const char *emit_dir, const char *lock_root_hex,
                       const char *reproduce_against, const char *work,
                       char *buf, size_t cap)
{
    char store_arg[4400];
    char emit_arg[4400];
    char lock_arg[4400];
    char repro_arg[4400];
    char work_arg[4400];
    snprintf(store_arg, sizeof(store_arg), "--store=%s", store);
    snprintf(emit_arg, sizeof(emit_arg), "--emit=%s", emit_dir);
    snprintf(lock_arg, sizeof(lock_arg), "--lock-root=%s", lock_root_hex);
    snprintf(work_arg, sizeof(work_arg), "--work=%s", work);
    const char *argv[9];
    size_t n = 0;
    argv[n++] = ZV_VERIFIER_BIN;
    argv[n++] = root_hex;
    argv[n++] = store_arg;
    argv[n++] = emit_arg;
    argv[n++] = lock_arg;
    if (reproduce_against) {
        snprintf(repro_arg, sizeof(repro_arg), "--reproduce-against=%s",
                 reproduce_against);
        argv[n++] = repro_arg;
    }
    argv[n++] = work_arg;
    argv[n] = NULL;
    return zcl_spawn_capture(argv, buf, cap, 300000);
}

/* The one attestation file a verifier run must have written. */
static bool zv_read_only_attestation(const char *store,
                                     struct vcs_package_attest *out)
{
    char dir[4400];
    snprintf(dir, sizeof(dir), "%s/attestations", store);
    DIR *d = opendir(dir);
    if (!d)
        return false;
    size_t count = 0;
    char name[256] = "";
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strlen(ent->d_name) != 64)
            continue;
        count++;
        snprintf(name, sizeof(name), "%s", ent->d_name);
    }
    closedir(d);
    if (count != 1)
        return false;
    char path[4400];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    uint8_t wire[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
    size_t wire_len = 0;
    if (!zv_read_file(path, wire, sizeof(wire), &wire_len))
        return false;
    return vcs_package_attest_parse(wire, wire_len, out) ==
           VCS_PACKAGE_ATTEST_OK;
}

static bool zv_write_key_file(const char *path, uint8_t seed, mode_t mode)
{
    struct privkey sk;
    struct pubkey pk;
    if (!zv_keypair(seed, &sk, &pk))
        return false;
    char hex[65];
    zv_hex_enc(sk.vch, 32, hex);
    return zv_write_file(path, hex, 64, mode);
}

static int t_verifier_e2e(void)
{
    int failures = 0;
    struct stat st;
    if (stat(ZV_VERIFIER_BIN, &st) != 0) {
        printf("  zcode_verify: e2e... FAIL (%s missing — run `make "
               "dev-bin` first)\n", ZV_VERIFIER_BIN);
        return 1;
    }
    char base[4400];
    snprintf(base, sizeof(base), "test-tmp/zv_e2e_%ld", (long)getpid());
    zv_rm_rf(base);
    if (!zv_mkdir_p(base)) {
        ZV_CHECK("e2e: fixture dir", false);
        return 1;
    }

    /* ── pass fixture: a tiny real C package builds and tests green ── */
    char store[4400];
    snprintf(store, sizeof(store), "%s/store", base);
    uint8_t package_root[32], release_id[32], recipe_root[32];
    bool fixture = zv_publish_fixture(
        store,
        "#include \"add.h\"\nint add(int a, int b) { return a + b; }\n",
        "#include \"add.h\"\n#include <string.h>\n"
        "int main(void) {\n"
        "    char buf[16];\n"
        "    memset(buf, 0, sizeof(buf));\n"
        "    return add(2, 3) == 5 && buf[0] == 0 ? 0 : 1;\n"
        "}\n",
        package_root, release_id, recipe_root);
    ZV_CHECK("e2e: pass fixture publishes", fixture);
    char key_path[4400];
    snprintf(key_path, sizeof(key_path), "%s/verifier.key", base);
    ZV_CHECK("e2e: key file writes (0600)",
             zv_write_key_file(key_path, 0x22, 0600));
    char work[4400];
    snprintf(work, sizeof(work), "%s/work", base);
    ZV_CHECK("e2e: work dir", zv_mkdir_p(work));

    char root_hex[65];
    zv_hex_enc(package_root, 32, root_hex);
    char out[2048];
    int rc = zv_run_verifier(root_hex, store, key_path, work, out,
                             sizeof(out));
    struct vcs_package_attest att;
    bool have_att = zv_read_only_attestation(store, &att);
    ZV_CHECK("e2e: verifier exits 0 and writes one attestation",
             rc == 0 && have_att);
    if (rc != 0)
        printf("  zcode_verify: e2e verifier rc=%d out=%s\n", rc, out);
    if (have_att) {
        struct pubkey vk;
        struct privkey vsk;
        zv_keypair(0x22, &vsk, &vk);
        if (vcs_package_attest_verify(&att) != VCS_PACKAGE_ATTEST_OK ||
            att.result_class != VCS_PACKAGE_ATTEST_RESULT_TEST_PASS ||
            memcmp(att.verifier_pubkey, vk.vch, 33) != 0 ||
            memcmp(att.package_root, package_root, 32) != 0 ||
            memcmp(att.recipe_root, recipe_root, 32) != 0 ||
            memcmp(att.release_id, release_id, 32) != 0 ||
            !att.test_ran || att.test_exit_code != 0)
            printf("  zcode_verify: e2e attest mismatch: verify=%d class=%s "
                   "signer=%d proot=%d rroot=%d rid=%d test_ran=%d exit=%u "
                   "isolation=%u detail=%s\n",
                   vcs_package_attest_verify(&att),
                   vcs_package_attest_result_string(att.result_class),
                   memcmp(att.verifier_pubkey, vk.vch, 33) == 0,
                   memcmp(att.package_root, package_root, 32) == 0,
                   memcmp(att.recipe_root, recipe_root, 32) == 0,
                   memcmp(att.release_id, release_id, 32) == 0,
                   att.test_ran, att.test_exit_code, att.isolation,
                   att.detail);
        ZV_CHECK("e2e: attestation verifies, test-pass, signer, roots",
                 vcs_package_attest_verify(&att) == VCS_PACKAGE_ATTEST_OK &&
                 att.result_class == VCS_PACKAGE_ATTEST_RESULT_TEST_PASS &&
                 memcmp(att.verifier_pubkey, vk.vch, 33) == 0 &&
                 memcmp(att.package_root, package_root, 32) == 0 &&
                 memcmp(att.recipe_root, recipe_root, 32) == 0 &&
                 memcmp(att.release_id, release_id, 32) == 0 &&
                 att.test_ran && att.test_exit_code == 0 &&
                 (att.isolation == VCS_PACKAGE_ATTEST_ISOLATION_FULL ||
                  att.isolation == VCS_PACKAGE_ATTEST_ISOLATION_DEGRADED));
    } else {
        ZV_CHECK("e2e: attestation verifies, test-pass, signer, roots",
                 false);
    }
    ZV_CHECK("e2e: produced binaries deleted (work tree empty)",
             zv_dir_is_empty(work));

    /* A world-readable key file is refused (exit 3, nothing signed). */
    {
        char store2[4400];
        snprintf(store2, sizeof(store2), "%s/store_keymode", base);
        uint8_t pr2[32], ri2[32], rr2[32];
        zv_publish_fixture(store2,
                           "#include \"add.h\"\nint add(int a, int b) { return a + b; }\n",
                           "#include \"add.h\"\nint main(void) { return add(2, 3) == 5 ? 0 : 1; }\n",
                           pr2, ri2, rr2);
        char bad_key[4400];
        snprintf(bad_key, sizeof(bad_key), "%s/bad.key", base);
        zv_write_key_file(bad_key, 0x22, 0644);
        char pr2_hex[65];
        zv_hex_enc(pr2, 32, pr2_hex);
        int krc = zv_run_verifier(pr2_hex, store2, bad_key, work, out,
                                  sizeof(out));
        ZV_CHECK("e2e: world-readable key refused, no attestation",
                 krc == 3 && !zv_read_only_attestation(store2, &att));
    }

    /* ── hostile: a syntax-error source builds a build-fail attestation ─ */
    {
        char store3[4400];
        snprintf(store3, sizeof(store3), "%s/store_buildfail", base);
        uint8_t pr3[32], ri3[32], rr3[32];
        bool f3 = zv_publish_fixture(
            store3,
            "#include \"add.h\"\nint add(int a, int b) { return a + ; }\n",
            "#include \"add.h\"\nint main(void) { return add(2, 3) == 5 ? 0 : 1; }\n",
            pr3, ri3, rr3);
        char pr3_hex[65];
        zv_hex_enc(pr3, 32, pr3_hex);
        int brc = zv_run_verifier(pr3_hex, store3, key_path, work, out,
                                  sizeof(out));
        struct vcs_package_attest batt;
        bool have_batt = zv_read_only_attestation(store3, &batt);
        ZV_CHECK("e2e: syntax-error source fails closed (build-fail)",
                 f3 && brc == 0 && have_batt &&
                 batt.result_class == VCS_PACKAGE_ATTEST_RESULT_BUILD_FAIL &&
                 (batt.detail_code == VCS_PACKAGE_ATTEST_DETAIL_COMPILE_ERROR ||
                  batt.detail_code == VCS_PACKAGE_ATTEST_DETAIL_LINK_ERROR) &&
                 vcs_package_attest_verify(&batt) == VCS_PACKAGE_ATTEST_OK);
        ZV_CHECK("e2e: hostile work tree cleaned", zv_dir_is_empty(work));
    }

    /* ── hostile: socket() in a test dies by seccomp (network denial) ── */
    {
        char store4[4400];
        snprintf(store4, sizeof(store4), "%s/store_socket", base);
        uint8_t pr4[32], ri4[32], rr4[32];
        bool f4 = zv_publish_fixture(
            store4,
            "#include \"add.h\"\nint add(int a, int b) { return a + b; }\n",
            "#include <sys/socket.h>\n#include <netinet/in.h>\n"
            "int main(void) {\n"
            "    int s = socket(AF_INET, SOCK_STREAM, 0);\n"
            "    return s >= 0 ? 0 : 1;\n"
            "}\n",
            pr4, ri4, rr4);
        char pr4_hex[65];
        zv_hex_enc(pr4, 32, pr4_hex);
        int src = zv_run_verifier(pr4_hex, store4, key_path, work, out,
                                  sizeof(out));
        struct vcs_package_attest satt;
        bool have_satt = zv_read_only_attestation(store4, &satt);
        bool socket_contract = f4 && src == 0 && have_satt &&
            vcs_package_attest_verify(&satt) == VCS_PACKAGE_ATTEST_OK;
#if defined(__APPLE__)
        /* Seatbelt denies socket creation.  The test treats that denial as
         * success, while the receipt records the qualified full-isolation
         * backend without borrowing Linux's seccomp signal claim. */
        socket_contract = socket_contract &&
            satt.isolation == VCS_PACKAGE_ATTEST_ISOLATION_FULL &&
            satt.result_class == VCS_PACKAGE_ATTEST_RESULT_TEST_PASS &&
            satt.detail_code == VCS_PACKAGE_ATTEST_DETAIL_NONE;
        ZV_CHECK("e2e: socket() test records full Seatbelt isolation",
                 socket_contract);
#else
        socket_contract = socket_contract &&
            satt.isolation == VCS_PACKAGE_ATTEST_ISOLATION_FULL &&
            satt.result_class == VCS_PACKAGE_ATTEST_RESULT_TEST_FAIL &&
            satt.detail_code == VCS_PACKAGE_ATTEST_DETAIL_TEST_SIGNAL;
        ZV_CHECK("e2e: socket() test killed by sandbox (test-fail/signal)",
                 socket_contract);
#endif
        if (!socket_contract)
            printf("  zcode_verify: socket e2e f4=%d src=%d have=%d "
                   "class=%s detail=%s text=%s out=%s\n", f4, src, have_satt,
                   vcs_package_attest_result_string(satt.result_class),
                   vcs_package_attest_detail_string(satt.detail_code),
                   satt.detail, out);
    }

    /* ── reproduction: --reproduce-against proves byte-identity ────── */
    {
        uint8_t lock_root[32];
        zv_pattern_root(0x66, lock_root);
        char lock_hex[65];
        zv_hex_enc(lock_root, 32, lock_hex);
        char emit1[4400], emit2[4400], emit3[4400];
        snprintf(emit1, sizeof(emit1), "%s/emit1", base);
        snprintf(emit2, sizeof(emit2), "%s/emit2", base);
        snprintf(emit3, sizeof(emit3), "%s/emit3", base);

        int e1 = zv_run_emit(root_hex, store, emit1, lock_hex, NULL, work,
                             out, sizeof(out));
        char report1[4400];
        snprintf(report1, sizeof(report1), "%s/build-report", emit1);
        struct stat rst;
        ZV_CHECK("e2e: emit build exits 0 and writes a build-report",
                 e1 == 0 && stat(report1, &rst) == 0);
        if (e1 != 0)
            printf("  zcode_verify: e2e emit rc=%d out=%s\n", e1, out);

        /* The third-party acceptance check: a second, independent build
         * of the same package reproduces the first byte-for-byte. */
        int e2 = zv_run_emit(root_hex, store, emit2, lock_hex, report1,
                             work, out, sizeof(out));
        ZV_CHECK("e2e: second build reproduces the first (MATCH)",
                 e2 == 0 && strstr(out, "reproduction=MATCH") != NULL);
        if (e2 != 0)
            printf("  zcode_verify: e2e reproduce rc=%d out=%s\n", e2, out);

        /* A tampered reference is rejected loudly: exit 6, and no MATCH
         * line is printed (the MISMATCH rule + detail go to stderr). */
        uint8_t rwire[VCS_PACKAGE_BUILD_MAX_WIRE_BYTES];
        size_t rwire_len = 0;
        struct vcs_package_build_receipt trec;
        bool tread = zv_read_file(report1, rwire, sizeof(rwire),
                                  &rwire_len) &&
                     vcs_package_build_parse(rwire, rwire_len, &trec) ==
                         VCS_PACKAGE_BUILD_OK &&
                     trec.output_count > 0;
        uint8_t *twire = NULL;
        size_t twire_len = 0;
        bool tser = false;
        if (tread) {
            trec.outputs[0].sha3[0] ^= 0xff;
            tser = vcs_package_build_serialize(&trec, &twire, &twire_len) ==
                   VCS_PACKAGE_BUILD_OK;
        }
        char tampered[4400];
        snprintf(tampered, sizeof(tampered), "%s/tampered-report", base);
        bool twrote = tser &&
                      zv_write_file(tampered, twire, twire_len, 0600);
        free(twire);
        ZV_CHECK("e2e: tampered reference builds", twrote);
        int e3 = zv_run_emit(root_hex, store, emit3, lock_hex, tampered,
                             work, out, sizeof(out));
        ZV_CHECK("e2e: tampered reference rejected loudly (exit 6)",
                 e3 == 6 && strstr(out, "reproduction=MATCH") == NULL);
        if (e3 != 6)
            printf("  zcode_verify: e2e reproduce-mismatch rc=%d out=%s\n",
                   e3, out);
    }

    zv_rm_rf(base);
    return failures;
}

/* ── programs: the executable a person actually runs ─────────────────── */

static bool zv_sha3_file(const char *path, uint8_t out[32], uint64_t *bytes)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    uint8_t buf[8192];
    uint64_t total = 0;
    size_t got;
    while ((got = fread(buf, 1, sizeof(buf), f)) > 0) {
        sha3_256_write(&c, buf, got);
        total += got;
    }
    bool ok = ferror(f) == 0;
    fclose(f);
    if (!ok)
        return false;
    sha3_256_finalize(&c, out);
    *bytes = total;
    return true;
}

static bool zv_read_receipt(const char *emit_dir,
                            struct vcs_package_build_receipt *out)
{
    char path[4400];
    snprintf(path, sizeof(path), "%s/build-report", emit_dir);
    uint8_t wire[VCS_PACKAGE_BUILD_MAX_WIRE_BYTES];
    size_t wire_len = 0;
    if (!zv_read_file(path, wire, sizeof(wire), &wire_len))
        return false;
    return vcs_package_build_parse(wire, wire_len, out) ==
           VCS_PACKAGE_BUILD_OK;
}

/* The receipt output whose install-relative path is exactly `want`. */
static const struct vcs_package_build_output *zv_output_named(
    const struct vcs_package_build_receipt *r, const char *want)
{
    for (size_t i = 0; i < r->output_count; i++)
        if (strcmp(r->outputs[i].path, want) == 0)
            return &r->outputs[i];
    return NULL;
}

/* A package that declares `app/main.c` is not only a library. The verifier
 * must compile that translation unit with the package's own flags, link it
 * against the package's own objects, the locked dependency closure and the
 * declared system libraries, and emit the EXECUTABLE as the install output
 * bin/<package short name> — reproducibly, and as a BUILD FAILURE when the
 * program does not compile. */
static int t_verifier_programs(void)
{
    int failures = 0;
    struct stat st;
    if (stat(ZV_VERIFIER_BIN, &st) != 0) {
        printf("  zcode_verify: programs... FAIL (%s missing — run `make "
               "dev-bin` first)\n", ZV_VERIFIER_BIN);
        return 1;
    }
    char base[4400];
    snprintf(base, sizeof(base), "test-tmp/zv_prog_%ld", (long)getpid());
    zv_rm_rf(base);
    if (!zv_mkdir_p(base)) {
        ZV_CHECK("programs: fixture dir", false);
        return 1;
    }

    static const char k_src[] =
        "#include \"add.h\"\nint add(int a, int b) { return a + b; }\n";
    static const char k_test[] =
        "#include \"add.h\"\n"
        "int main(void) { return add(2, 3) == 5 ? 0 : 1; }\n";
    /* Deterministic output, and it CALLS the library the package ships, so
     * a program that was never linked against the package's own objects
     * cannot pass this. */
    static const char k_program[] =
        "#include \"add.h\"\n#include <stdio.h>\n"
        "int main(void) {\n"
        "    printf(\"addpkg sum=%d\\n\", add(20, 22));\n"
        "    return 0;\n"
        "}\n";

    char store[4400];
    snprintf(store, sizeof(store), "%s/store", base);
    uint8_t package_root[32], release_id[32], recipe_root[32];
    bool fixture = zv_publish_fixture_ex(store, k_src, k_test, k_program,
                                         package_root, release_id,
                                         recipe_root);
    ZV_CHECK("programs: a fixture declaring app/main.c publishes", fixture);
    if (!fixture) {
        zv_rm_rf(base);
        return failures;
    }
    char root_hex[65];
    zv_hex_enc(package_root, 32, root_hex);
    uint8_t lock_root[32];
    zv_pattern_root(0x77, lock_root);
    char lock_hex[65];
    zv_hex_enc(lock_root, 32, lock_hex);

    /* Two emits from two DIFFERENT work roots. The work root is the only
     * input that differs, so an absolute build path that reached the
     * executable's bytes shows up below as a hash divergence. */
    char work1[4400], work2[4400], emit1[4400], emit2[4400];
    snprintf(work1, sizeof(work1), "%s/work-a", base);
    snprintf(work2, sizeof(work2), "%s/work-bbbbbbbbbbbbbbbbbbbb", base);
    snprintf(emit1, sizeof(emit1), "%s/emit1", base);
    snprintf(emit2, sizeof(emit2), "%s/emit2", base);
    ZV_CHECK("programs: work dirs", zv_mkdir_p(work1) && zv_mkdir_p(work2));

    char out[2048];
    int e1 = zv_run_emit(root_hex, store, emit1, lock_hex, NULL, work1, out,
                         sizeof(out));
    if (e1 != 0)
        printf("  zcode_verify: programs emit rc=%d out=%s\n", e1, out);
    struct vcs_package_build_receipt rec1;
    bool read1 = e1 == 0 && zv_read_receipt(emit1, &rec1);
    const struct vcs_package_build_output *prog_out =
        read1 ? zv_output_named(&rec1, "bin/addpkg") : NULL;
    ZV_CHECK("programs: the receipt commits bin/<package short name>",
             read1 && prog_out != NULL &&
                 rec1.result_class == VCS_PACKAGE_BUILD_RESULT_TEST_PASS &&
                 vcs_package_build_installable(&rec1));
    ZV_CHECK("programs: the archive and the public header still emit",
             read1 && zv_output_named(&rec1, "lib/libaddpkg.a") != NULL &&
                 zv_output_named(&rec1, "include/add.h") != NULL);

    char prog_path[4500];
    snprintf(prog_path, sizeof(prog_path), "%s/bin/addpkg", emit1);
    struct stat pst;
    bool emitted_exec = stat(prog_path, &pst) == 0 && S_ISREG(pst.st_mode) &&
                        (pst.st_mode & 0111) != 0;
    ZV_CHECK("programs: the emitted program is a regular executable file",
             emitted_exec);
    uint8_t emitted_hash[32];
    uint64_t emitted_bytes = 0;
    bool hashed = emitted_exec &&
                  zv_sha3_file(prog_path, emitted_hash, &emitted_bytes);
    ZV_CHECK("programs: the emitted bytes are exactly what the receipt says",
             hashed && prog_out && emitted_bytes == prog_out->bytes &&
                 memcmp(emitted_hash, prog_out->sha3, 32) == 0);

    /* Run it. The verifier never executes a program — this is the test
     * doing what the person who installed the package would do. */
    char ran[512];
    ran[0] = '\0';
    const char *run_argv[] = { prog_path, NULL };
    int prc = emitted_exec
        ? zcl_spawn_capture(run_argv, ran, sizeof(ran), 30000)
        : -1;
    ZV_CHECK("programs: running it prints the linked library's answer",
             prc == 0 && strstr(ran, "addpkg sum=42") != NULL);
    if (prc != 0)
        printf("  zcode_verify: programs run rc=%d out=%s\n", prc, ran);

    int e2 = zv_run_emit(root_hex, store, emit2, lock_hex, NULL, work2, out,
                         sizeof(out));
    struct vcs_package_build_receipt rec2;
    bool read2 = e2 == 0 && zv_read_receipt(emit2, &rec2);
    const struct vcs_package_build_output *prog_out2 =
        read2 ? zv_output_named(&rec2, "bin/addpkg") : NULL;
    ZV_CHECK("programs: two work roots produce byte-identical program bytes",
             prog_out && prog_out2 && prog_out2->bytes == prog_out->bytes &&
                 memcmp(prog_out2->sha3, prog_out->sha3, 32) == 0);
    if (e2 != 0)
        printf("  zcode_verify: programs second emit rc=%d out=%s\n", e2,
               out);

    /* And the whole receipt still reproduces — the acceptance signal the
     * install lifecycle's reproduce track depends on. */
    char report1[4500];
    snprintf(report1, sizeof(report1), "%s/build-report", emit1);
    char emit3[4400];
    snprintf(emit3, sizeof(emit3), "%s/emit3", base);
    int e3 = zv_run_emit(root_hex, store, emit3, lock_hex, report1, work2,
                         out, sizeof(out));
    ZV_CHECK("programs: a build carrying a program still reproduces (MATCH)",
             e3 == 0 && strstr(out, "reproduction=MATCH") != NULL);
    if (e3 != 0)
        printf("  zcode_verify: programs reproduce rc=%d out=%s\n", e3, out);

    /* A broken program is a BUILD FAILURE, never a quietly missing output:
     * an application that does not compile must not be installable. */
    {
        char store_bad[4400];
        char emit_bad[4400];
        snprintf(store_bad, sizeof(store_bad), "%s/store_progfail", base);
        snprintf(emit_bad, sizeof(emit_bad), "%s/emit_progfail", base);
        uint8_t br[32], bi[32], brr[32];
        bool bf = zv_publish_fixture_ex(
            store_bad, k_src, k_test,
            "#include \"add.h\"\nint main(void) { return add(1, ; }\n",
            br, bi, brr);
        char br_hex[65];
        zv_hex_enc(br, 32, br_hex);
        int erc = zv_run_emit(br_hex, store_bad, emit_bad, lock_hex, NULL,
                              work1, out, sizeof(out));
        struct vcs_package_build_receipt bad;
        bool bad_read = erc == 0 && zv_read_receipt(emit_bad, &bad);
        char bad_prog[4500];
        snprintf(bad_prog, sizeof(bad_prog), "%s/bin/addpkg", emit_bad);
        ZV_CHECK("programs: a program that fails to compile fails the build",
                 bf && bad_read &&
                     bad.result_class ==
                         VCS_PACKAGE_BUILD_RESULT_BUILD_FAIL &&
                     !vcs_package_build_installable(&bad) &&
                     bad.output_count == 0 &&
                     stat(bad_prog, &pst) != 0);
        if (!bad_read)
            printf("  zcode_verify: programs build-fail rc=%d out=%s\n", erc,
                   out);
    }

    zv_rm_rf(base);
    return failures;
}

int test_zcode_verify(void)
{
    printf("\n=== zcode_verify: external verifier attestations ===\n");
    int failures = 0;
    failures += t_codec();
    failures += t_signature();
    failures += t_policy();
    failures += t_quorum();
    failures += t_build_receipt_v2();
    failures += t_reproduce();
    failures += t_command();
    failures += t_attest_import();
    failures += t_attest_offer();
    failures += t_attest_pull();
    failures += t_attest_publish_gate();
    failures += t_work_publish_gate();
    failures += t_task_publish_gate();
    failures += t_verifier_e2e();
    failures += t_verifier_programs();
    printf("=== zcode_verify complete: %d failure(s) ===\n", failures);
    return failures;
}
