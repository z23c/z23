/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_attest_transport — how a signed ZCLATT attestation MOVES
 * (lib/vcs/package_attest_transport.*).
 *
 * Coverage:
 *   1. Transport root: pure and deterministic (the same wire yields the
 *      same root across two independent calls; two different wires yield
 *      different roots), and REFUSED by name before any root is offered
 *      for bytes that are not a canonical ZCLATT wire or whose embedded
 *      signature does not verify.
 *   2. offer -> admit round trip over a real package store on a temp
 *      datadir: the publisher files a wire, offers it as a blob, both
 *      nodes derive the SAME transport root from the exact bytes, and the
 *      receiver admits it — the filed bytes are byte-identical to the
 *      original wire.
 *   3. The binding check: admitting with a WRONG expect_package_root is
 *      ERR_BINDING and files NOTHING; the correct root files it. This is
 *      what stops a pointer in the attestation namespace from delivering
 *      an attestation for a DIFFERENT package.
 *   4. Idempotence (identical re-admission is OK with filed=false,
 *      already_present=true) and ERR_CONFLICT (a same-name object that
 *      does not read back identical is never overwritten).
 *   5. ADMITTING IS NOT ACCEPTING: an attestation from a signer this node
 *      has never approved, and one carrying a FAILURE result class, both
 *      file successfully.
 *
 * Every datadir is a ./test-tmp/<prefix>_<pid>_<tag> tree built by the
 * harness helper; the live datadir is never opened or written. */

#include "test/test_core.h"

#include "core/uint256.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "vcs/blob_store.h"
#include "vcs/package_attest.h"
#include "vcs/package_attest_transport.h"
#include "vcs/package_store.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZAT_CHECK(name, expr) do {                                          \
    if (expr) { printf("  zcode_attest_transport: %s... OK\n", (name)); }   \
    else { printf("  zcode_attest_transport: %s... FAIL\n", (name));        \
           failures++; }                                                    \
} while (0)

/* ── small fixtures ─────────────────────────────────────────────────── */

static void zat_hex_enc(const uint8_t *in, size_t len, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[in[i] & 0xf];
    }
    out[2 * len] = '\0';
}

static void zat_pattern_root(uint8_t seed, uint8_t out[32])
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(seed + i);
}

static bool zat_mkdir_p(const char *path)
{
    char buf[1024];
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

static bool zat_write_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    size_t written = fwrite(data, 1, len, f);
    return fclose(f) == 0 && written == len;
}

static bool zat_read_file(const char *path, uint8_t *out, size_t cap,
                          size_t *out_len)
{
    *out_len = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t len = fread(out, 1, cap, f);
    bool ok = !ferror(f) && len > 0;
    fclose(f);
    if (!ok)
        return false;
    *out_len = len;
    return true;
}

static bool zat_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* ── attestation fixtures (the codec's own signing path) ────────────── */

static bool zat_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static bool zat_sign_attest(struct vcs_package_attest *a, struct privkey *sk)
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
 * mirroring the field sets the external verifier produces. */
static bool zat_attest(struct vcs_package_attest *a, uint8_t cls,
                       const uint8_t package_root[32],
                       const uint8_t release_id[32],
                       const uint8_t recipe_root[32], uint8_t signer_seed)
{
    struct privkey sk;
    struct pubkey pk;
    if (!zat_keypair(signer_seed, &sk, &pk))
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
    case VCS_PACKAGE_ATTEST_RESULT_BUILD_FAIL:
        a->test_ran = false;
        a->detail_code = VCS_PACKAGE_ATTEST_DETAIL_COMPILE_ERROR;
        snprintf(a->detail, sizeof(a->detail),
                 "gcc: src/x.c:4:5: error: expected expression");
        a->compilers[0].outcome = VCS_PACKAGE_ATTEST_OUTCOME_FAIL;
        break;
    default:
        return false;
    }
    memcpy(a->verifier_pubkey, pk.vch, VCS_PACKAGE_ATTEST_PUBKEY_BYTES);
    return zat_sign_attest(a, &sk);
}

/* Build one signed wire plus its id. `wire` must hold at least
 * VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES. */
static bool zat_wire(uint8_t cls, const uint8_t package_root[32],
                     const uint8_t release_id[32],
                     const uint8_t recipe_root[32], uint8_t signer_seed,
                     uint8_t *wire, size_t *wire_len,
                     uint8_t id_out[VCS_PACKAGE_ATTEST_ID_BYTES])
{
    struct vcs_package_attest a;
    if (!zat_attest(&a, cls, package_root, release_id, recipe_root,
                    signer_seed))
        return false;
    uint8_t *buf = NULL;
    size_t len = 0;
    if (vcs_package_attest_serialize(&a, &buf, &len) !=
            VCS_PACKAGE_ATTEST_OK ||
        len == 0 || len > VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES) {
        free(buf);
        return false;
    }
    bool ok = vcs_package_attest_id(&a, id_out) == VCS_PACKAGE_ATTEST_OK;
    if (ok) {
        memcpy(wire, buf, len);
        *wire_len = len;
    }
    free(buf);
    return ok;
}

/* ── 1. the pure transport root ─────────────────────────────────────── */

static int t_root(void)
{
    int failures = 0;
    uint8_t pkg[32], rel[32], recipe[32];
    zat_pattern_root(0x10, pkg);
    zat_pattern_root(0x40, rel);
    zat_pattern_root(0x80, recipe);

    uint8_t wire[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
    size_t wire_len = 0;
    uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
    bool built = zat_wire(VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pkg, rel,
                          recipe, 0x22, wire, &wire_len, id);
    ZAT_CHECK("root: attestation wire builds", built);
    if (!built)
        return failures + 1;

    /* Determinism: two independent calls over the same bytes agree, and
     * the transport root is exactly vcs_blob_root() of those bytes. */
    struct vcs_package_attest_transport_outcome o1;
    struct vcs_package_attest_transport_outcome o2;
    enum vcs_package_attest_transport_result r1 =
        vcs_package_attest_transport_root(wire, wire_len, &o1);
    enum vcs_package_attest_transport_result r2 =
        vcs_package_attest_transport_root(wire, wire_len, &o2);
    uint8_t blob_root[32];
    bool blob_ok = vcs_blob_root(wire, wire_len, blob_root);
    ZAT_CHECK("root: the same wire yields the same root twice",
              r1 == VCS_PACKAGE_ATTEST_TRANSPORT_OK &&
              r2 == VCS_PACKAGE_ATTEST_TRANSPORT_OK &&
              o1.result == VCS_PACKAGE_ATTEST_TRANSPORT_OK &&
              memcmp(o1.transport_root, o2.transport_root, 32) == 0);
    ZAT_CHECK("root: the transport root IS the blob root of the wire",
              blob_ok && memcmp(o1.transport_root, blob_root, 32) == 0);
    ZAT_CHECK("root: the outcome carries the recomputed attestation id",
              memcmp(o1.attestation_id, id, sizeof(id)) == 0 &&
              o1.blob_error == VCS_BLOB_OK &&
              o1.attest_error == VCS_PACKAGE_ATTEST_OK);

    /* Two DIFFERENT wires must not collide: the root commits the exact
     * signed bytes, and these differ in the attested package root. */
    uint8_t other_pkg[32];
    zat_pattern_root(0x11, other_pkg);
    uint8_t wire_b[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
    size_t wire_b_len = 0;
    uint8_t id_b[VCS_PACKAGE_ATTEST_ID_BYTES];
    struct vcs_package_attest_transport_outcome ob;
    bool built_b = zat_wire(VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, other_pkg,
                            rel, recipe, 0x22, wire_b, &wire_b_len, id_b);
    ZAT_CHECK("root: a second, different wire builds", built_b);
    ZAT_CHECK("root: different wires yield different roots",
              built_b &&
              vcs_package_attest_transport_root(wire_b, wire_b_len, &ob) ==
                  VCS_PACKAGE_ATTEST_TRANSPORT_OK &&
              memcmp(ob.transport_root, o1.transport_root, 32) != 0);

    /* A non-canonical wire has no transport root: the bytes are parsed
     * and verified BEFORE anything is advertised. */
    {
        uint8_t broken[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
        memcpy(broken, wire, wire_len);
        broken[0] = (uint8_t)(broken[0] ^ 0xffu); /* 'Z' of "ZCLATT\r\n" */
        struct vcs_package_attest_transport_outcome ob2;
        enum vcs_package_attest_transport_result rr =
            vcs_package_attest_transport_root(broken, wire_len, &ob2);
        uint8_t zero[32] = {0};
        ZAT_CHECK("root: a non-canonical wire is refused naming the "
                  "grammar rule",
                  rr == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ATTEST &&
                  ob2.result == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ATTEST &&
                  ob2.attest_error == VCS_PACKAGE_ATTEST_ERR_WIRE_MAGIC &&
                  memcmp(ob2.transport_root, zero, 32) == 0);
    }

    /* A tampered SIGNATURE parses but does not verify: still no root.
     * The flipped byte sits in r (the first half of the compact
     * signature), so the low-S canonical rule is untouched and the
     * failure is the ECDSA check itself. */
    {
        uint8_t tampered[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
        memcpy(tampered, wire, wire_len);
        size_t sig_off = wire_len - VCS_PACKAGE_ATTEST_SIGNATURE_BYTES;
        tampered[sig_off] = (uint8_t)(tampered[sig_off] ^ 0x01u);
        struct vcs_package_attest_transport_outcome ob3;
        enum vcs_package_attest_transport_result rr =
            vcs_package_attest_transport_root(tampered, wire_len, &ob3);
        uint8_t zero[32] = {0};
        ZAT_CHECK("root: a tampered signature is refused naming the "
                  "signature rule",
                  rr == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ATTEST &&
                  ob3.attest_error == VCS_PACKAGE_ATTEST_ERR_SIG_VERIFY &&
                  memcmp(ob3.transport_root, zero, 32) == 0);
    }

    /* Null arguments are named, never dereferenced. */
    {
        struct vcs_package_attest_transport_outcome ob4;
        ZAT_CHECK("root: a NULL wire is named",
                  vcs_package_attest_transport_root(NULL, wire_len, &ob4) ==
                      VCS_PACKAGE_ATTEST_TRANSPORT_ERR_NULL &&
                  ob4.result == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_NULL);
        ZAT_CHECK("root: a NULL outcome is named",
                  vcs_package_attest_transport_root(wire, wire_len, NULL) ==
                      VCS_PACKAGE_ATTEST_TRANSPORT_ERR_NULL);
    }
    return failures;
}

/* ── 2. offer -> admit over a real store ────────────────────────────── */

struct zat_node {
    char datadir[512];
    char zcode[600];
    struct vcs_package_store *store;
};

static bool zat_node_open(struct zat_node *n, const char *tag)
{
    test_make_tmpdir(n->datadir, sizeof(n->datadir), "zcode_attest_transport",
                     tag);
    snprintf(n->zcode, sizeof(n->zcode), "%s/zcode", n->datadir);
    n->store = vcs_package_store_open(n->datadir,
                                      VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    return n->store != NULL;
}

static void zat_node_close(struct zat_node *n)
{
    if (n->store)
        vcs_package_store_close(n->store);
    n->store = NULL;
    test_rm_rf_recursive(n->datadir);
}

static void zat_attest_path(const struct zat_node *n,
                            const uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES],
                            char *out, size_t out_n)
{
    char id_hex[2 * VCS_PACKAGE_ATTEST_ID_BYTES + 1];
    zat_hex_enc(id, VCS_PACKAGE_ATTEST_ID_BYTES, id_hex);
    snprintf(out, out_n, "%s/attestations/%s", n->zcode, id_hex);
}

static int t_offer_admit(void)
{
    int failures = 0;
    uint8_t pkg[32], rel[32], recipe[32];
    zat_pattern_root(0x21, pkg);
    zat_pattern_root(0x51, rel);
    zat_pattern_root(0x91, recipe);

    uint8_t wire[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
    size_t wire_len = 0;
    uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
    bool built = zat_wire(VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pkg, rel,
                          recipe, 0x22, wire, &wire_len, id);
    ZAT_CHECK("round trip: attestation wire builds", built);
    if (!built)
        return failures + 1;

    struct zat_node pub = {0};
    struct zat_node rcv = {0};
    bool opened = zat_node_open(&pub, "publisher") &&
                  zat_node_open(&rcv, "receiver");
    ZAT_CHECK("round trip: both stores open", opened);
    if (!opened) {
        zat_node_close(&pub);
        zat_node_close(&rcv);
        return failures + 1;
    }

    /* The publisher files its own attestation through the single filer. */
    bool filed = false;
    bool already = false;
    enum vcs_package_attest_transport_result fr =
        vcs_package_attest_transport_file(pub.zcode, wire, wire_len, id,
                                          &filed, &already);
    ZAT_CHECK("round trip: the publisher files the wire",
              fr == VCS_PACKAGE_ATTEST_TRANSPORT_OK && filed && !already);

    /* Offering re-reads, re-parses, re-verifies, re-derives the id, and
     * admits the exact bytes as a blob. Nothing is announced. */
    struct vcs_package_attest_transport_outcome off;
    enum vcs_package_attest_transport_result orr =
        vcs_package_attest_transport_offer(pub.store, pub.zcode, id, &off);
    ZAT_CHECK("round trip: offer publishes the blob and names its root",
              orr == VCS_PACKAGE_ATTEST_TRANSPORT_OK &&
              memcmp(off.attestation_id, id, sizeof(id)) == 0);

    /* Re-offering identical bytes is idempotent and yields the same root. */
    struct vcs_package_attest_transport_outcome off2;
    ZAT_CHECK("round trip: re-offering identical bytes is idempotent",
              vcs_package_attest_transport_offer(pub.store, pub.zcode, id,
                                                 &off2) ==
                  VCS_PACKAGE_ATTEST_TRANSPORT_OK &&
              memcmp(off2.transport_root, off.transport_root, 32) == 0);

    /* Offering an id this node does not hold is ERR_ABSENT, by name. */
    {
        uint8_t ghost_id[VCS_PACKAGE_ATTEST_ID_BYTES];
        zat_pattern_root(0x07, ghost_id);
        struct vcs_package_attest_transport_outcome ga;
        ZAT_CHECK("round trip: offering an absent id is named",
                  vcs_package_attest_transport_offer(pub.store, pub.zcode,
                                                     ghost_id, &ga) ==
                      VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ABSENT);
    }

    /* The swarm's job is moving the exact bytes; both nodes derive the
     * SAME transport root from them, which is what makes a POINTER
     * resolvable at all. */
    uint8_t delivered_root[32];
    enum vcs_blob_result br =
        vcs_blob_put_to(rcv.store, wire, wire_len, delivered_root);
    ZAT_CHECK("round trip: the receiver derives the publisher's root",
              br == VCS_BLOB_OK &&
              memcmp(delivered_root, off.transport_root, 32) == 0);

    struct vcs_package_attest_transport_outcome adm;
    enum vcs_package_attest_transport_result ar =
        vcs_package_attest_transport_admit(rcv.store, rcv.zcode,
                                           delivered_root, NULL, &adm);
    ZAT_CHECK("round trip: the receiver admits and files it",
              ar == VCS_PACKAGE_ATTEST_TRANSPORT_OK && adm.filed &&
              !adm.already_present &&
              memcmp(adm.attestation_id, id, sizeof(id)) == 0 &&
              memcmp(adm.attestation.package_root, pkg, 32) == 0);

    /* The filed bytes are the signed bytes, unchanged. */
    {
        char path[1200];
        zat_attest_path(&rcv, id, path, sizeof(path));
        uint8_t back[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES + 1];
        size_t back_len = 0;
        bool read_ok = zat_read_file(path, back, sizeof(back), &back_len);
        ZAT_CHECK("round trip: the filed bytes are byte-identical",
                  read_ok && back_len == wire_len &&
                  memcmp(back, wire, wire_len) == 0);
    }

    /* Identical re-admission is OK and files nothing new. */
    struct vcs_package_attest_transport_outcome adm2;
    ZAT_CHECK("round trip: re-admitting the same blob is idempotent",
              vcs_package_attest_transport_admit(rcv.store, rcv.zcode,
                                                 delivered_root, NULL,
                                                 &adm2) ==
                  VCS_PACKAGE_ATTEST_TRANSPORT_OK &&
              !adm2.filed && adm2.already_present);

    /* A root the receiver does not hold is the blob layer's rule, named. */
    {
        uint8_t absent[32];
        zat_pattern_root(0xa5, absent);
        struct vcs_package_attest_transport_outcome ab;
        ZAT_CHECK("round trip: an unheld transport root is named",
                  vcs_package_attest_transport_admit(rcv.store, rcv.zcode,
                                                     absent, NULL, &ab) ==
                      VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BLOB &&
                  ab.blob_error == VCS_BLOB_ERR_ABSENT);
    }

    zat_node_close(&pub);
    zat_node_close(&rcv);
    return failures;
}

/* ── 3. the binding check ───────────────────────────────────────────── */

static int t_binding(void)
{
    int failures = 0;
    uint8_t pkg[32], rel[32], recipe[32], wrong_pkg[32];
    zat_pattern_root(0x31, pkg);
    zat_pattern_root(0x61, rel);
    zat_pattern_root(0xb1, recipe);
    zat_pattern_root(0x32, wrong_pkg);

    uint8_t wire[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
    size_t wire_len = 0;
    uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
    bool built = zat_wire(VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pkg, rel,
                          recipe, 0x44, wire, &wire_len, id);
    ZAT_CHECK("binding: attestation wire builds", built);
    if (!built)
        return failures + 1;

    struct zat_node n = {0};
    bool opened = zat_node_open(&n, "binding");
    ZAT_CHECK("binding: store opens", opened);
    if (!opened) {
        zat_node_close(&n);
        return failures + 1;
    }
    uint8_t root[32];
    ZAT_CHECK("binding: the blob is delivered",
              vcs_blob_put_to(n.store, wire, wire_len, root) == VCS_BLOB_OK);

    char path[1200];
    zat_attest_path(&n, id, path, sizeof(path));

    /* A pointer keyed on one package root that delivers an attestation
     * for ANOTHER package is refused — and files nothing at all. */
    struct vcs_package_attest_transport_outcome bad;
    enum vcs_package_attest_transport_result br =
        vcs_package_attest_transport_admit(n.store, n.zcode, root, wrong_pkg,
                                           &bad);
    ZAT_CHECK("binding: a wrong expected package root is refused",
              br == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BINDING &&
              bad.result == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BINDING &&
              !bad.filed && !bad.already_present);
    ZAT_CHECK("binding: a binding failure files NOTHING",
              !zat_file_exists(path));

    /* The correct root files it. */
    struct vcs_package_attest_transport_outcome good;
    ZAT_CHECK("binding: the correct expected package root files it",
              vcs_package_attest_transport_admit(n.store, n.zcode, root, pkg,
                                                 &good) ==
                  VCS_PACKAGE_ATTEST_TRANSPORT_OK &&
              good.filed && !good.already_present &&
              zat_file_exists(path));

    zat_node_close(&n);
    return failures;
}

/* ── 4. a same-name object that is not these bytes ──────────────────── */

static int t_conflict(void)
{
    int failures = 0;
    uint8_t pkg[32], rel[32], recipe[32];
    zat_pattern_root(0x41, pkg);
    zat_pattern_root(0x71, rel);
    zat_pattern_root(0xc1, recipe);

    uint8_t wire[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
    size_t wire_len = 0;
    uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
    bool built = zat_wire(VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pkg, rel,
                          recipe, 0x55, wire, &wire_len, id);
    ZAT_CHECK("conflict: attestation wire builds", built);
    if (!built)
        return failures + 1;

    struct zat_node n = {0};
    bool opened = zat_node_open(&n, "conflict");
    ZAT_CHECK("conflict: store opens", opened);
    if (!opened) {
        zat_node_close(&n);
        return failures + 1;
    }
    uint8_t root[32];
    ZAT_CHECK("conflict: the blob is delivered",
              vcs_blob_put_to(n.store, wire, wire_len, root) == VCS_BLOB_OK);

    /* Pre-place a DIFFERENT object at this attestation id. The id is the
     * content hash, so this is impossible for honest wires: fail closed
     * rather than overwrite whatever is already there. */
    char dir[1000];
    snprintf(dir, sizeof(dir), "%s/attestations", n.zcode);
    ZAT_CHECK("conflict: attestations dir prepared", zat_mkdir_p(dir));
    char path[1200];
    zat_attest_path(&n, id, path, sizeof(path));
    static const char k_squatter[] = "not-an-attestation";
    ZAT_CHECK("conflict: a squatting object is pre-placed",
              zat_write_file(path, k_squatter, sizeof(k_squatter) - 1u));

    struct vcs_package_attest_transport_outcome out;
    ZAT_CHECK("conflict: admission fails closed on a same-name object",
              vcs_package_attest_transport_admit(n.store, n.zcode, root, pkg,
                                                 &out) ==
                  VCS_PACKAGE_ATTEST_TRANSPORT_ERR_CONFLICT &&
              out.result == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_CONFLICT &&
              !out.filed && !out.already_present);

    uint8_t back[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES + 1];
    size_t back_len = 0;
    bool read_ok = zat_read_file(path, back, sizeof(back), &back_len);
    ZAT_CHECK("conflict: the pre-placed bytes are untouched",
              read_ok && back_len == sizeof(k_squatter) - 1u &&
              memcmp(back, k_squatter, back_len) == 0);

    zat_node_close(&n);
    return failures;
}

/* ── 5. admitting is not accepting ──────────────────────────────────── */

/* Both cases below MUST succeed. Refusing evidence at intake would let a
 * node's own allowlist decide what it is allowed to SEE, and a quorum you
 * can only observe once you already agree with it proves nothing. The
 * approved-verifier policy is applied later, by `zcode package verify`;
 * these datadirs carry no allowlist at all, so BOTH signers here are
 * unapproved by construction. */
static int t_admitting_is_not_accepting(void)
{
    int failures = 0;
    uint8_t pkg[32], rel[32], recipe[32];
    zat_pattern_root(0x51, pkg);
    zat_pattern_root(0x81, rel);
    zat_pattern_root(0xd1, recipe);

    struct zat_node n = {0};
    bool opened = zat_node_open(&n, "not_accepting");
    ZAT_CHECK("not-accepting: store opens", opened);
    if (!opened) {
        zat_node_close(&n);
        return failures + 1;
    }

    /* (a) A signer this node has never approved. */
    {
        uint8_t wire[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
        bool built = zat_wire(VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, pkg, rel,
                              recipe, 0x66, wire, &wire_len, id);
        ZAT_CHECK("not-accepting: unapproved signer's wire builds", built);
        uint8_t root[32];
        struct vcs_package_attest_transport_outcome out;
        char path[1200];
        zat_attest_path(&n, id, path, sizeof(path));
        ZAT_CHECK("not-accepting: an unapproved signer's attestation files",
                  built &&
                  vcs_blob_put_to(n.store, wire, wire_len, root) ==
                      VCS_BLOB_OK &&
                  vcs_package_attest_transport_admit(n.store, n.zcode, root,
                                                     pkg, &out) ==
                      VCS_PACKAGE_ATTEST_TRANSPORT_OK &&
                  out.filed && zat_file_exists(path));
    }

    /* (b) A FAILURE result class. Negative evidence is evidence. */
    {
        uint8_t wire[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
        bool built = zat_wire(VCS_PACKAGE_ATTEST_RESULT_BUILD_FAIL, pkg, rel,
                              recipe, 0x77, wire, &wire_len, id);
        ZAT_CHECK("not-accepting: build-fail wire builds", built);
        uint8_t root[32];
        struct vcs_package_attest_transport_outcome out;
        char path[1200];
        zat_attest_path(&n, id, path, sizeof(path));
        ZAT_CHECK("not-accepting: a FAILURE result class still files",
                  built &&
                  vcs_blob_put_to(n.store, wire, wire_len, root) ==
                      VCS_BLOB_OK &&
                  vcs_package_attest_transport_admit(n.store, n.zcode, root,
                                                     pkg, &out) ==
                      VCS_PACKAGE_ATTEST_TRANSPORT_OK &&
                  out.filed &&
                  out.attestation.result_class ==
                      VCS_PACKAGE_ATTEST_RESULT_BUILD_FAIL &&
                  zat_file_exists(path));
    }

    /* (c) A package this node has never seen. The attested root is not in
     * any local store here, and the attestation still files. */
    {
        uint8_t ghost_pkg[32], ghost_rel[32], ghost_recipe[32];
        zat_pattern_root(0xe1, ghost_pkg);
        zat_pattern_root(0xe2, ghost_rel);
        zat_pattern_root(0xe3, ghost_recipe);
        uint8_t wire[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
        bool built = zat_wire(VCS_PACKAGE_ATTEST_RESULT_TEST_PASS, ghost_pkg,
                              ghost_rel, ghost_recipe, 0x66, wire, &wire_len,
                              id);
        ZAT_CHECK("not-accepting: ghost-package wire builds", built);
        uint8_t root[32];
        struct vcs_package_attest_transport_outcome out;
        char path[1200];
        zat_attest_path(&n, id, path, sizeof(path));
        ZAT_CHECK("not-accepting: an attestation for an unheld package files",
                  built &&
                  vcs_blob_put_to(n.store, wire, wire_len, root) ==
                      VCS_BLOB_OK &&
                  vcs_package_attest_transport_admit(n.store, n.zcode, root,
                                                     ghost_pkg, &out) ==
                      VCS_PACKAGE_ATTEST_TRANSPORT_OK &&
                  out.filed && zat_file_exists(path));
    }

    zat_node_close(&n);
    return failures;
}

int test_zcode_attest_transport(void)
{
    printf("\n=== zcode_attest_transport: attestations over the blob swarm "
           "===\n");
    int failures = 0;
    failures += t_root();
    failures += t_offer_admit();
    failures += t_binding();
    failures += t_conflict();
    failures += t_admitting_is_not_accepting();
    printf("=== zcode_attest_transport complete: %d failure(s) ===\n",
           failures);
    return failures;
}
