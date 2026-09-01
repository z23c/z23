/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_release — the `zcode release` command layer
 * (tools/command/native_zcode_release_command.c), the Sovereign Registry
 * sign/verify/anchor/prove surface.
 *
 * The zid codec and the anchor-domain tree are covered by test_zid; the
 * domain store by test_zid's zid_domain_store cases. This group covers
 * the HANDLER wiring: the security contracts, the named errors, and the
 * batch/proof round-trip that a verifier actually depends on.
 *
 * Coverage:
 *   1. `sign` REFUSES a seed file whose permissions are looser than
 *      0600/0400. The seed is a master key; this is a security contract,
 *      not a nicety, so it is proven for every loosened mode.
 *   2. The seed never appears in any output field, and the key it derives
 *      is the one that signed — so the refusal above is the only thing
 *      standing between a world-readable file and a stolen identity.
 *   3. Batch load determinism: the same directory contents fold to the
 *      same domain root regardless of the order the files were created
 *      in (and therefore regardless of readdir order).
 *   4. A non-decoding .zid file is a hard BATCH_LOAD error that NAMES the
 *      offending file — never a silently smaller batch, which would
 *      change what an already-issued proof means.
 *   5. A missing releases directory is 0 releases, not a load error.
 *   6. The named verify errors — DOC_EXPIRED, BAD_SIGNATURE,
 *      NOT_A_RELEASE_BODY, DOC_DECODE_FAILED — each fire on the right
 *      input and ONLY on it.
 *   7. prove → verify --proof --root round-trips; a tampered proof gives
 *      NOT_IN_BATCH; and batch inclusion is reported SEPARATELY from
 *      signature validity (a doc can be correctly signed and not in the
 *      batch, and both facts stay visible).
 *
 * Hermetic: per-pid ./test-tmp datadirs, no network, no wallet, no live
 * node. node_rpc_call is stubbed for the whole group so the anchor
 * handler can NEVER reach a running node. The exact offline op_return_hex
 * is funded and mined only in the RAM-only simnet fixture, then projected
 * through the production explorer index; nothing is broadcast.
 */

#include "test/test_core.h"

#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "crypto/ed25519.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/zanc.h"
#include "platform/time_compat.h"
#include "test/transaction_lab_simnet.h"
#include "zid/zid.h"
#include "zanc/zanc.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── RPC containment (see test_epoch.c) ────────────────────────────── */

static char *zr_rpc_stub(const char *method, const char *params_json)
{
    (void)params_json;
    char *out = malloc(256); // raw-alloc-ok:test-fixture
    if (!out)
        return NULL;
    snprintf(out, 256,
             "{\"error\":{\"code\":-1,\"message\":\"test stub refused %s\"}}",
             method ? method : "(null)");
    return out;
}

/* ── in-process command runner ─────────────────────────────────────── */

struct zr_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void zr_cmd_init(struct zr_cmd *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.zcode_release_test.v1");
}

static void zr_cmd_free(struct zr_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static const char *zr_str(const struct zcl_command_reply *r, const char *key)
{
    const struct json_value *v = json_get(&r->data, key);
    return (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
}

static bool zr_str_is(const struct zcl_command_reply *r, const char *key,
                      const char *want)
{
    const char *got = zr_str(r, key);
    return got && strcmp(got, want) == 0;
}

static int64_t zr_int(const struct zcl_command_reply *r, const char *key,
                      int64_t absent)
{
    const struct json_value *v = json_get(&r->data, key);
    return (v && v->type == JSON_INT) ? json_get_int(v) : absent;
}

static int zr_bool(const struct zcl_command_reply *r, const char *key)
{
    const struct json_value *v = json_get(&r->data, key);
    if (!v || v->type != JSON_BOOL)
        return -1;
    return json_get_bool(v) ? 1 : 0;
}

static bool zr_code_is(const struct zcl_command_reply *r, const char *code)
{
    return strcmp(r->error.code, code) == 0;
}

static bool zr_ok(const struct zcl_command_reply *r)
{
    return r->status == ZCL_COMMAND_STATUS_PASSED &&
           r->exit_code == ZCL_COMMAND_EXIT_OK;
}

/* ── fixture ───────────────────────────────────────────────────────── */

struct zr_fixture {
    char datadir[256];
    char seedfile[320];
    uint8_t seed[32];
    char seed_hex[65];
};

static bool zr_write_seed(const char *path, const char *hex, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return false;
    size_t n = strlen(hex);
    bool ok = write(fd, hex, n) == (ssize_t)n;
    close(fd);
    return ok && chmod(path, mode) == 0;
}

static bool zr_fixture_init(struct zr_fixture *f, const char *tag,
                            uint8_t seed_fill)
{
    memset(f, 0, sizeof(*f));
    snprintf(f->datadir, sizeof(f->datadir), "./test-tmp/%d_zrel_%s",
             (int)getpid(), tag);
    mkdir("./test-tmp", 0755);
    char rm[512];
    snprintf(rm, sizeof(rm), "rm -rf %s", f->datadir);
    (void)system(rm);
    if (mkdir(f->datadir, 0755) != 0)
        return false;
    memset(f->seed, seed_fill, 32);
    HexStr(f->seed, 32, false, f->seed_hex, sizeof(f->seed_hex));
    snprintf(f->seedfile, sizeof(f->seedfile), "%s/seed.hex", f->datadir);
    return zr_write_seed(f->seedfile, f->seed_hex, 0600);
}

static void zr_fixture_free(struct zr_fixture *f)
{
    char rm[512];
    snprintf(rm, sizeof(rm), "rm -rf %s", f->datadir);
    (void)system(rm);
}

/* Sign one release into <datadir>/zcode/releases. Returns a malloc'd
 * doc_hex on success (caller frees), NULL on failure. */
static char *zr_sign(const struct zr_fixture *f, const char *name,
                     const char *version, uint8_t root_fill, int64_t expiry,
                     struct zcl_command_reply *out_reply)
{
    struct zr_cmd c;
    zr_cmd_init(&c);
    uint8_t root[32];
    memset(root, root_fill, 32);
    char root_hex[65];
    HexStr(root, 32, false, root_hex, sizeof(root_hex));
    (void)json_push_kv_str(&c.input, "datadir", f->datadir);
    (void)json_push_kv_str(&c.input, "name", name);
    (void)json_push_kv_str(&c.input, "version", version);
    (void)json_push_kv_str(&c.input, "root", root_hex);
    (void)json_push_kv_str(&c.input, "seed_file", f->seedfile);
    if (expiry > 0)
        (void)json_push_kv_int(&c.input, "expiry", expiry);
    zcl_native_handle_zcode_release_sign(&c.request, &c.reply);

    char *hex = NULL;
    const char *got = zr_str(&c.reply, "doc_hex");
    if (zr_ok(&c.reply) && got) {
        hex = malloc(strlen(got) + 1); // raw-alloc-ok:test-fixture
        if (hex)
            memcpy(hex, got, strlen(got) + 1);
    }
    if (out_reply) {
        /* Shallow hand-off of the interesting scalars only. */
        out_reply->status = c.reply.status;
        out_reply->exit_code = c.reply.exit_code;
        snprintf(out_reply->error.code, sizeof(out_reply->error.code), "%s",
                 c.reply.error.code);
    }
    zr_cmd_free(&c);
    return hex;
}

/* Run `zcode release verify --doc=<hex>` (optionally with proof+root). */
static void zr_verify(const char *doc_hex, const char *proof_hex,
                      const char *root_hex, struct zr_cmd *c)
{
    zr_cmd_init(c);
    (void)json_push_kv_str(&c->input, "doc", doc_hex);
    if (proof_hex)
        (void)json_push_kv_str(&c->input, "proof", proof_hex);
    if (root_hex)
        (void)json_push_kv_str(&c->input, "root", root_hex);
    zcl_native_handle_zcode_release_verify(&c->request, &c->reply);
}

/* ── 1. seed-file permission contract ──────────────────────────────── */

static int test_zr_seed_perms(void)
{
    int failures = 0;
    struct zr_fixture f;

    printf("zcode_release seed: fixture... ");
    if (zr_fixture_init(&f, "perms", 0x11)) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    /* A master seed at 0644 is readable by every account on the box. The
     * handler must refuse to USE it, not warn about it — a warning that
     * still signs has already leaked nothing but has taught the operator
     * the file is fine. */
    static const struct { mode_t mode; bool accept; } cases[] = {
        {0600, true},  {0400, true},
        {0644, false}, {0640, false}, {0660, false}, {0604, false},
        {0700, false}, {0666, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        printf("zcode_release seed: mode %04o is %s... ",
               (unsigned)cases[i].mode, cases[i].accept ? "accepted"
                                                        : "REFUSED");
        bool set = chmod(f.seedfile, cases[i].mode) == 0;
        struct zr_cmd c;
        zr_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_str(&c.input, "name", "pkg");
        (void)json_push_kv_str(&c.input, "version", "1.0.0");
        char root_hex[65];
        uint8_t root[32];
        memset(root, 0x22, 32);
        HexStr(root, 32, false, root_hex, sizeof(root_hex));
        (void)json_push_kv_str(&c.input, "root", root_hex);
        (void)json_push_kv_str(&c.input, "seed_file", f.seedfile);
        zcl_native_handle_zcode_release_sign(&c.request, &c.reply);

        bool ok;
        if (cases[i].accept) {
            ok = set && zr_ok(&c.reply) && zr_str(&c.reply, "doc_hex");
        } else {
            /* Refused, named, and with the exact remedy in the message. */
            ok = set && c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
                 c.reply.exit_code == ZCL_COMMAND_EXIT_INVALID &&
                 zr_code_is(&c.reply, "BAD_SEED_FILE") &&
                 strstr(c.reply.error.message, "chmod 600") != NULL &&
                 !zr_str(&c.reply, "doc_hex");
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    /* A seed that is not 64 hex chars is refused under the same code —
     * the file is a master key, so every rejection path is a refusal. */
    printf("zcode_release seed: a short/non-hex seed file is refused... ");
    {
        char bad[320];
        snprintf(bad, sizeof(bad), "%s/bad.hex", f.datadir);
        bool set = zr_write_seed(bad, "not hex at all, not 64 chars either!!",
                                 0600);
        struct zr_cmd c;
        zr_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_str(&c.input, "name", "pkg");
        (void)json_push_kv_str(&c.input, "version", "1.0.0");
        char root_hex[65];
        uint8_t root[32];
        memset(root, 0x22, 32);
        HexStr(root, 32, false, root_hex, sizeof(root_hex));
        (void)json_push_kv_str(&c.input, "root", root_hex);
        (void)json_push_kv_str(&c.input, "seed_file", bad);
        zcl_native_handle_zcode_release_sign(&c.request, &c.reply);
        bool ok = set && zr_code_is(&c.reply, "BAD_SEED_FILE") &&
                  !zr_str(&c.reply, "doc_hex");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    zr_fixture_free(&f);
    return failures;
}

/* ── 2. the seed never leaves the handler ──────────────────────────── */

/* Serialize the whole value and scan the bytes. Checking named fields
 * would only prove the seed is absent from the fields we thought to look
 * at; serializing covers every key and every value, including ones added
 * later. Returns true if `needle` occurs anywhere. */
static bool zr_json_contains(const struct json_value *v, const char *needle)
{
    size_t need = json_write(v, NULL, 0);
    char *buf = malloc(need + 2); // raw-alloc-ok:test-fixture
    if (!buf)
        return true; /* cannot prove absence — fail the assertion, not pass it */
    (void)json_write(v, buf, need + 1);
    buf[need] = '\0';
    bool hit = strstr(buf, needle) != NULL;
    free(buf);
    return hit;
}

static int test_zr_seed_hygiene(void)
{
    int failures = 0;
    struct zr_fixture f;

    printf("zcode_release hygiene: fixture... ");
    if (zr_fixture_init(&f, "hygiene", 0x37)) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    printf("zcode_release hygiene: the seed appears nowhere in the reply, "
           "yet the doc is signed by the key it derives... ");
    {
        struct zr_cmd c;
        zr_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_str(&c.input, "name", "sovereign");
        (void)json_push_kv_str(&c.input, "version", "1.2.3");
        char root_hex[65];
        uint8_t root[32];
        memset(root, 0x44, 32);
        HexStr(root, 32, false, root_hex, sizeof(root_hex));
        (void)json_push_kv_str(&c.input, "root", root_hex);
        (void)json_push_kv_str(&c.input, "seed_file", f.seedfile);
        zcl_native_handle_zcode_release_sign(&c.request, &c.reply);

        /* The pubkey the seed derives — proof the seed WAS used. */
        uint8_t pk[32], sk[32];
        ed25519_keypair(pk, sk, f.seed);
        char pk_hex[65];
        HexStr(pk, 32, false, pk_hex, sizeof(pk_hex));

        /* Uppercase form too: a hex-case slip would still be a leak. */
        char seed_upper[65];
        for (int i = 0; i < 64; i++) {
            char ch = f.seed_hex[i];
            seed_upper[i] = (ch >= 'a' && ch <= 'f') ? (char)(ch - 32) : ch;
        }
        seed_upper[64] = '\0';

        bool ok = zr_ok(&c.reply) &&
                  zr_str_is(&c.reply, "master_pubkey", pk_hex) &&
                  !zr_json_contains(&c.reply.data, f.seed_hex) &&
                  !zr_json_contains(&c.reply.data, seed_upper) &&
                  /* the error envelope is a string surface too */
                  strstr(c.reply.error.message, f.seed_hex) == NULL &&
                  strstr(c.reply.error.evidence, f.seed_hex) == NULL;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    printf("zcode_release hygiene: the saved .zid file holds the doc, never "
           "the seed... ");
    {
        char path[512];
        snprintf(path, sizeof(path), "%s/zcode/releases/sovereign-1.2.3.zid",
                 f.datadir);
        int fd = open(path, O_RDONLY);
        char buf[4096];
        ssize_t n = fd >= 0 ? read(fd, buf, sizeof(buf) - 1) : -1;
        if (fd >= 0)
            close(fd);
        if (n > 0)
            buf[n] = '\0';
        bool ok = n > 0 && strstr(buf, f.seed_hex) == NULL;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    zr_fixture_free(&f);
    return failures;
}

/* ── 3. batch determinism ──────────────────────────────────────────── */

/* Sign `n` releases in the order given by `order`, then anchor and return
 * the domain root (malloc'd, caller frees) or NULL. */
static char *zr_root_for_order(const char *tag, const int *order, int n)
{
    static const char *names[3] = {"alpha", "bravo", "charlie"};
    static const char *versions[3] = {"1.0.0", "2.1.0", "0.9.9"};
    static const uint8_t roots[3] = {0xA1, 0xB2, 0xC3};

    struct zr_fixture f;
    if (!zr_fixture_init(&f, tag, 0x5C))
        return NULL;
    bool ok = true;
    for (int i = 0; i < n && ok; i++) {
        int k = order[i];
        /* Fixed expiry: the batch root must be a function of the docs, and
         * a wall-clock default would make two runs differ for no reason. */
        char *hex = zr_sign(&f, names[k], versions[k], roots[k],
                            4102444800LL /* 2100-01-01 */, NULL);
        ok = hex != NULL;
        free(hex);
    }
    char *root = NULL;
    if (ok) {
        struct zr_cmd c;
        zr_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_int(&c.input, "tip", 100);
        zcl_native_handle_zcode_release_anchor(&c.request, &c.reply);
        const char *got = zr_str(&c.reply, "domain_root");
        if (zr_ok(&c.reply) && got && zr_int(&c.reply, "releases", -1) == n) {
            root = malloc(strlen(got) + 1); // raw-alloc-ok:test-fixture
            if (root)
                memcpy(root, got, strlen(got) + 1);
        }
        zr_cmd_free(&c);
    }
    zr_fixture_free(&f);
    return root;
}

static int test_zr_batch_determinism(void)
{
    int failures = 0;

    printf("zcode_release batch: the same dir contents fold to the same "
           "domain root in any creation order... ");
    {
        static const int fwd[3] = {0, 1, 2};
        static const int rev[3] = {2, 1, 0};
        static const int mid[3] = {1, 2, 0};
        char *a = zr_root_for_order("det_a", fwd, 3);
        char *b = zr_root_for_order("det_b", rev, 3);
        char *c = zr_root_for_order("det_c", mid, 3);
        bool ok = a && b && c && strlen(a) == 64 && strcmp(a, b) == 0 &&
                  strcmp(a, c) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        free(a);
        free(b);
        free(c);
    }

    /* A DIFFERENT leaf set must fold to a different root — otherwise the
     * equality above would be satisfied by a constant. */
    printf("zcode_release batch: a different leaf set folds to a different "
           "root (the equality above is not vacuous)... ");
    {
        static const int fwd[3] = {0, 1, 2};
        static const int two[2] = {0, 1};
        char *three = zr_root_for_order("det_d", fwd, 3);
        char *pair = zr_root_for_order("det_e", two, 2);
        bool ok = three && pair && strcmp(three, pair) != 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        free(three);
        free(pair);
    }

    return failures;
}

/* ── 4/5. batch load failure + missing directory ───────────────────── */

static int test_zr_batch_load(void)
{
    int failures = 0;
    struct zr_fixture f;

    printf("zcode_release load: fixture... ");
    if (zr_fixture_init(&f, "load", 0x6D)) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    /* A missing releases dir is 0 releases, NOT a load error: the two must
     * stay distinguishable, because "you have not signed anything yet" and
     * "your release directory is corrupt" have opposite remedies. */
    printf("zcode_release load: a missing releases dir is NO_RELEASES, not "
           "a BATCH_LOAD error... ");
    {
        struct zr_cmd c;
        zr_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_int(&c.input, "tip", 5);
        zcl_native_handle_zcode_release_anchor(&c.request, &c.reply);
        bool ok = c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
                  zr_code_is(&c.reply, "NO_RELEASES") &&
                  c.reply.error.retryable &&
                  !zr_code_is(&c.reply, "BATCH_LOAD");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    char *good = zr_sign(&f, "good", "1.0.0", 0x71, 4102444800LL, NULL);
    printf("zcode_release load: one signed release makes a batch of 1... ");
    {
        struct zr_cmd c;
        zr_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_int(&c.input, "tip", 5);
        zcl_native_handle_zcode_release_anchor(&c.request, &c.reply);
        bool ok = good && zr_ok(&c.reply) &&
                  zr_int(&c.reply, "releases", -1) == 1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    /* A junk .zid must be a HARD error naming the file. Skipping it would
     * silently shrink the leaf set, and a previously-issued proof against
     * the old root would stop verifying with no explanation anywhere. */
    printf("zcode_release load: a non-decoding .zid is a hard BATCH_LOAD "
           "error that NAMES the file... ");
    {
        char junk[512];
        snprintf(junk, sizeof(junk), "%s/zcode/releases/junk-9.9.9.zid",
                 f.datadir);
        int fd = open(junk, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        bool wrote = fd >= 0 && write(fd, "deadbeef\n", 9) == 9;
        if (fd >= 0)
            close(fd);

        struct zr_cmd c;
        zr_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_int(&c.input, "tip", 5);
        zcl_native_handle_zcode_release_anchor(&c.request, &c.reply);
        bool ok = wrote && c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
                  zr_code_is(&c.reply, "BATCH_LOAD") &&
                  strstr(c.reply.error.message, "junk-9.9.9.zid") != NULL &&
                  /* and it did NOT quietly anchor the surviving one */
                  zr_int(&c.reply, "releases", -1) == -1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);

        /* prove takes the same load path and must refuse identically. */
        printf("zcode_release load: prove refuses the same junk file... ");
        struct zr_cmd p;
        zr_cmd_init(&p);
        (void)json_push_kv_str(&p.input, "datadir", f.datadir);
        (void)json_push_kv_str(&p.input, "name", "good");
        (void)json_push_kv_str(&p.input, "version", "1.0.0");
        (void)json_push_kv_str(&p.input, "domain", "never-anchored");
        zcl_native_handle_zcode_release_prove(&p.request, &p.reply);
        bool pok = zr_code_is(&p.reply, "BATCH_LOAD") &&
                   strstr(p.reply.error.message, "junk-9.9.9.zid") != NULL;
        if (pok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&p);

        (void)unlink(junk);
    }

    /* A non-.zid file in the same directory is ignored, not an error. */
    printf("zcode_release load: a non-.zid file in the releases dir is "
           "ignored... ");
    {
        char note[512];
        snprintf(note, sizeof(note), "%s/zcode/releases/NOTES.txt", f.datadir);
        int fd = open(note, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        bool wrote = fd >= 0 && write(fd, "not a doc\n", 10) == 10;
        if (fd >= 0)
            close(fd);
        struct zr_cmd c;
        zr_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_int(&c.input, "tip", 5);
        zcl_native_handle_zcode_release_anchor(&c.request, &c.reply);
        bool ok = wrote && zr_ok(&c.reply) &&
                  zr_int(&c.reply, "releases", -1) == 1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    free(good);
    zr_fixture_free(&f);
    return failures;
}

/* ── 6. the named verify errors ────────────────────────────────────── */

/* Verify `doc_hex` and require EXACTLY `want_code` — every other named
 * failure mode must NOT fire on this input. */
static int zr_expect_verify_code(const char *what, const char *doc_hex,
                                 const char *want_code)
{
    static const char *codes[] = {"DOC_EXPIRED", "BAD_SIGNATURE",
                                  "NOT_A_RELEASE_BODY", "DOC_DECODE_FAILED",
                                  "BAD_DOC_HEX"};
    printf("zcode_release verify: %s -> %s (and no other code)... ", what,
           want_code);
    struct zr_cmd c;
    zr_verify(doc_hex, NULL, NULL, &c);
    bool ok = c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
              zr_code_is(&c.reply, want_code);
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); i++)
        if (strcmp(codes[i], want_code) != 0 && zr_code_is(&c.reply, codes[i]))
            ok = false;
    zr_cmd_free(&c);
    if (ok) { printf("OK\n"); return 0; }
    printf("FAIL\n");
    return 1;
}

static int test_zr_verify_errors(void)
{
    int failures = 0;
    struct zr_fixture f;

    printf("zcode_release verify: fixture... ");
    if (zr_fixture_init(&f, "verr", 0x2E)) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    int64_t now = platform_time_wall_unix();

    /* The control: a good doc verifies, and none of the failure codes
     * fire. Without this the four negatives could all be passing for the
     * wrong reason. */
    char *good = zr_sign(&f, "ctl", "1.0.0", 0x81, now + 86400, NULL);
    printf("zcode_release verify: a well-formed unexpired doc is valid... ");
    {
        struct zr_cmd c;
        zr_verify(good ? good : "", NULL, NULL, &c);
        bool ok = good && zr_ok(&c.reply) && zr_bool(&c.reply, "valid") == 1 &&
                  zr_str_is(&c.reply, "name", "ctl") &&
                  zr_str_is(&c.reply, "version", "1.0.0") &&
                  c.reply.error.code[0] == '\0';
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    /* DOC_EXPIRED — signed correctly, but its expiry has passed. */
    {
        char *expired = zr_sign(&f, "old", "0.1.0", 0x82, now - 60, NULL);
        if (expired) {
            failures += zr_expect_verify_code("an expired doc", expired,
                                              "DOC_EXPIRED");
            free(expired);
        } else { printf("zcode_release verify: expired fixture... FAIL\n");
                 failures++; }
    }

    /* BAD_SIGNATURE — a byte flipped in the trailing 64-byte signature.
     * Everything else about the doc is well-formed and unexpired, so only
     * the signature check can reject it. */
    printf("zcode_release verify: fixture for a tampered signature... ");
    {
        uint8_t wire[ZID_DOC_MAX];
        size_t n = good ? (size_t)ParseHex(good, wire, sizeof(wire)) : 0;
        if (n > 64) {
            wire[n - 1] ^= 0x01;
            char tampered[ZID_DOC_MAX * 2 + 1];
            HexStr(wire, n, false, tampered, sizeof(tampered));
            printf("OK\n");
            failures += zr_expect_verify_code("a doc with a flipped signature "
                                              "byte", tampered,
                                              "BAD_SIGNATURE");
        } else { printf("FAIL\n"); failures++; }
    }

    /* NOT_A_RELEASE_BODY — a correctly signed, unexpired zid doc whose
     * body is not a ZIDR release record. This is the "signed for something
     * else" case, and it must never be reported as a bad signature. */
    printf("zcode_release verify: fixture for a non-release body... ");
    {
        struct zid_doc doc;
        const uint8_t body[] = "ZIDX not a release record at all";
        bool signed_ok = zid_doc_sign(&doc, body, (uint16_t)sizeof(body) - 1,
                                      1, (uint64_t)(now + 86400), f.seed);
        uint8_t wire[ZID_DOC_MAX];
        size_t n = signed_ok ? zid_doc_encode(wire, sizeof(wire), &doc) : 0;
        if (n > 0) {
            char hex[ZID_DOC_MAX * 2 + 1];
            HexStr(wire, n, false, hex, sizeof(hex));
            printf("OK\n");
            failures += zr_expect_verify_code("a signed doc whose body is not "
                                              "ZIDR", hex,
                                              "NOT_A_RELEASE_BODY");
        } else { printf("FAIL\n"); failures++; }
    }

    /* DOC_DECODE_FAILED — even-length hex that is not a zid doc wire. */
    {
        failures += zr_expect_verify_code(
            "hex that is not a zid doc wire",
            "0102030405060708090a0b0c0d0e0f101112131415161718",
            "DOC_DECODE_FAILED");
    }

    /* And the input-shape rejection stays separate from the decode
     * rejection: odd-length/non-hex never reaches the decoder. */
    {
        failures += zr_expect_verify_code("odd-length hex", "abc",
                                          "BAD_DOC_HEX");
        failures += zr_expect_verify_code("non-hex input", "zzzz",
                                          "BAD_DOC_HEX");
    }

    printf("zcode_release verify: neither --doc nor --file is MISSING_DOC... ");
    {
        struct zr_cmd c;
        zr_cmd_init(&c);
        zcl_native_handle_zcode_release_verify(&c.request, &c.reply);
        bool ok = zr_code_is(&c.reply, "MISSING_DOC");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    printf("zcode_release verify: --proof without --root is "
           "INCOMPLETE_PROOF... ");
    {
        struct zr_cmd c;
        zr_verify(good ? good : "", "00", NULL, &c);
        bool ok = zr_code_is(&c.reply, "INCOMPLETE_PROOF");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    free(good);
    zr_fixture_free(&f);
    return failures;
}

/* ── 7. prove/verify round-trip + inclusion vs signature ───────────── */

static int test_zr_prove_verify(void)
{
    int failures = 0;
    struct zr_fixture f;

    printf("zcode_release prove: fixture (3 signed releases, anchored)... ");
    if (!zr_fixture_init(&f, "prove", 0x4B)) { printf("FAIL\n"); return 1; }

    int64_t expiry = platform_time_wall_unix() + 86400;
    char *doc_a = zr_sign(&f, "alpha", "1.0.0", 0xA1, expiry, NULL);
    char *doc_b = zr_sign(&f, "bravo", "2.0.0", 0xB2, expiry, NULL);
    char *doc_c = zr_sign(&f, "charlie", "3.0.0", 0xC3, expiry, NULL);

    char anchored_root[65] = {0};
    {
        struct zr_cmd c;
        zr_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_int(&c.input, "tip", 4242);
        zcl_native_handle_zcode_release_anchor(&c.request, &c.reply);
        const char *r = zr_str(&c.reply, "domain_root");
        bool ok = doc_a && doc_b && doc_c && zr_ok(&c.reply) && r &&
                  zr_int(&c.reply, "releases", -1) == 3 &&
                  zr_bool(&c.reply, "domain_stored") == 1;
        if (r)
            snprintf(anchored_root, sizeof(anchored_root), "%s", r);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    /* Independent recomputation of the batch root from the three doc
     * wires: digest each, sort the digests by bytes, fold. This proves
     * the canonical order directly rather than by observing that three
     * creation orders happened to agree — if the handler ever folded in
     * readdir order, this is the assertion that catches it. */
    printf("zcode_release prove: the anchored root equals an independent "
           "fold of the byte-sorted record digests... ");
    {
        const char *docs[3] = {doc_a, doc_b, doc_c};
        uint8_t digests[3][32];
        bool built = true;
        for (int i = 0; i < 3 && built; i++) {
            uint8_t wire[ZID_DOC_MAX];
            size_t n = docs[i] ? (size_t)ParseHex(docs[i], wire, sizeof(wire))
                               : 0;
            built = n > 0;
            if (built)
                zid_record_digest(digests[i], wire, n);
        }
        /* Byte-sort (three elements: an explicit insertion sort). */
        for (int i = 1; i < 3; i++)
            for (int j = i; j > 0 &&
                 memcmp(digests[j - 1], digests[j], 32) > 0; j--) {
                uint8_t t[32];
                memcpy(t, digests[j - 1], 32);
                memcpy(digests[j - 1], digests[j], 32);
                memcpy(digests[j], t, 32);
            }
        uint8_t root[32];
        char root_hex[65] = {0};
        if (built && zid_tree_root_from_digests(
                         (const uint8_t (*)[32])digests, 3, root))
            HexStr(root, 32, false, root_hex, sizeof(root_hex));
        bool ok = built && root_hex[0] &&
                  strcmp(root_hex, anchored_root) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* prove reads the STORED leaf set (source "domain_table"), not a fresh
     * directory fold — that is what makes an issued proof stable. */
    char proof_b[ZID_PROOF_WIRE_MAX * 2 + 1] = {0};
    char proof_root[65] = {0};
    printf("zcode_release prove: prove reads the stored leaf set and its "
           "root equals the anchored root... ");
    {
        struct zr_cmd c;
        zr_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_str(&c.input, "name", "bravo");
        (void)json_push_kv_str(&c.input, "version", "2.0.0");
        zcl_native_handle_zcode_release_prove(&c.request, &c.reply);
        const char *p = zr_str(&c.reply, "proof");
        const char *r = zr_str(&c.reply, "domain_root");
        if (p) snprintf(proof_b, sizeof(proof_b), "%s", p);
        if (r) snprintf(proof_root, sizeof(proof_root), "%s", r);
        bool ok = zr_ok(&c.reply) && p && r &&
                  zr_str_is(&c.reply, "source", "domain_table") &&
                  zr_int(&c.reply, "num_leaves", -1) == 3 &&
                  strcmp(proof_root, anchored_root) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    printf("zcode_release prove: prove -> verify --proof --root "
           "round-trips... ");
    {
        struct zr_cmd c;
        zr_verify(doc_b ? doc_b : "", proof_b, proof_root, &c);
        bool ok = zr_ok(&c.reply) && zr_bool(&c.reply, "valid") == 1 &&
                  zr_bool(&c.reply, "batch_included") == 1 &&
                  zr_str_is(&c.reply, "batch_root", proof_root) &&
                  zr_int(&c.reply, "batch_num_leaves", -1) == 3 &&
                  zr_str_is(&c.reply, "name", "bravo");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    printf("zcode_release prove: a tampered proof gives NOT_IN_BATCH... ");
    {
        char bad[sizeof(proof_b)];
        snprintf(bad, sizeof(bad), "%s", proof_b);
        size_t n = strlen(bad);
        /* Flip the last sibling nibble — a well-formed wire that no longer
         * folds to the root. */
        bad[n - 1] = (bad[n - 1] == 'a') ? 'b' : 'a';
        struct zr_cmd c;
        zr_verify(doc_b ? doc_b : "", bad, proof_root, &c);
        bool ok = n > 0 && c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
                  zr_code_is(&c.reply, "NOT_IN_BATCH") &&
                  zr_bool(&c.reply, "batch_included") == 0 &&
                  /* the signature verdict is still reported */
                  zr_bool(&c.reply, "valid") == 1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    printf("zcode_release prove: a stale root gives NOT_IN_BATCH... ");
    {
        char wrong[65];
        snprintf(wrong, sizeof(wrong), "%s", proof_root);
        wrong[0] = (wrong[0] == '0') ? '1' : '0';
        struct zr_cmd c;
        zr_verify(doc_b ? doc_b : "", proof_b, wrong, &c);
        bool ok = zr_code_is(&c.reply, "NOT_IN_BATCH") &&
                  zr_bool(&c.reply, "batch_included") == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    /* THE separation that matters. A doc can be correctly signed by its
     * publisher AND not be in the batch this root commits. Collapsing the
     * two would let "the signature is fine" read as "this release is in
     * the anchored set" — which is the whole point of anchoring. */
    printf("zcode_release prove: a correctly-signed doc that is NOT in the "
           "batch reports BOTH facts separately... ");
    {
        struct zr_cmd c;
        /* alpha's doc against bravo's proof: valid signature, wrong leaf. */
        zr_verify(doc_a ? doc_a : "", proof_b, proof_root, &c);
        bool ok = zr_code_is(&c.reply, "NOT_IN_BATCH") &&
                  zr_bool(&c.reply, "valid") == 1 &&   /* signature: good */
                  zr_bool(&c.reply, "batch_included") == 0 && /* batch: no */
                  zr_str_is(&c.reply, "name", "alpha") &&
                  zr_str(&c.reply, "record_digest") != NULL;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    /* ...and the converse: an INVALID signature never reaches the batch
     * check, so a bad doc can never be reported as "included". */
    printf("zcode_release prove: an invalid signature is rejected before any "
           "batch verdict is published... ");
    {
        uint8_t wire[ZID_DOC_MAX];
        size_t n = doc_b ? (size_t)ParseHex(doc_b, wire, sizeof(wire)) : 0;
        bool ok = false;
        if (n > 64) {
            wire[n - 1] ^= 0x01;
            char tampered[ZID_DOC_MAX * 2 + 1];
            HexStr(wire, n, false, tampered, sizeof(tampered));
            struct zr_cmd c;
            zr_verify(tampered, proof_b, proof_root, &c);
            ok = zr_code_is(&c.reply, "BAD_SIGNATURE") &&
                 zr_bool(&c.reply, "valid") == 0 &&
                 zr_bool(&c.reply, "batch_included") == -1;
            zr_cmd_free(&c);
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("zcode_release prove: a release absent from the anchored leaf set "
           "is RELEASE_NOT_FOUND... ");
    {
        struct zr_cmd c;
        zr_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_str(&c.input, "name", "bravo");
        (void)json_push_kv_str(&c.input, "version", "9.9.9");
        zcl_native_handle_zcode_release_prove(&c.request, &c.reply);
        bool ok = zr_code_is(&c.reply, "RELEASE_NOT_FOUND");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    /* Domains are separate registries: a never-anchored domain falls back
     * to a directory fold and SAYS so. */
    printf("zcode_release prove: a never-anchored domain falls back to the "
           "release dir and labels the source... ");
    {
        struct zr_cmd c;
        zr_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_str(&c.input, "name", "bravo");
        (void)json_push_kv_str(&c.input, "version", "2.0.0");
        (void)json_push_kv_str(&c.input, "domain", "zdesc");
        zcl_native_handle_zcode_release_prove(&c.request, &c.reply);
        bool ok = zr_ok(&c.reply) &&
                  zr_str_is(&c.reply, "source", "release_dir") &&
                  zr_bool(&c.reply, "anchored") == 0 &&
                  zr_str_is(&c.reply, "domain", "zdesc");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    printf("zcode_release prove: an invalid domain name is BAD_DOMAIN... ");
    {
        struct zr_cmd c;
        zr_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_str(&c.input, "name", "bravo");
        (void)json_push_kv_str(&c.input, "version", "2.0.0");
        (void)json_push_kv_str(&c.input, "domain", "Not A Domain");
        zcl_native_handle_zcode_release_prove(&c.request, &c.reply);
        bool ok = zr_code_is(&c.reply, "BAD_DOMAIN");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        zr_cmd_free(&c);
    }

    free(doc_a);
    free(doc_b);
    free(doc_c);
    zr_fixture_free(&f);
    return failures;
}

/* ── 8. exact command bytes mined and projected ───────────────────── */

static int test_zr_mined_anchor(void)
{
    int failures = 0;
    struct zr_fixture f;
    printf("zcode_release simnet: signed release fixture... ");
    if (!zr_fixture_init(&f, "simnet", 0x7D)) {
        printf("FAIL\n");
        return 1;
    }
    char *doc = zr_sign(&f, "sovereign", "4.2.0", 0xD4,
                        4102444800LL, NULL);
    if (doc) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    char root_hex[65] = {0};
    char script_hex[257] = {0};
    printf("zcode_release simnet: command emits one deterministic ZANC "
           "anchor... ");
    {
        struct zr_cmd c;
        zr_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_int(&c.input, "tip", 4242);
        zcl_native_handle_zcode_release_anchor(&c.request, &c.reply);
        const char *root = zr_str(&c.reply, "domain_root");
        const char *script = zr_str(&c.reply, "op_return_hex");
        bool ok = doc && zr_ok(&c.reply) && root && strlen(root) == 64 &&
                  script && strlen(script) > 0 &&
                  strlen(script) < sizeof(script_hex) &&
                  zr_int(&c.reply, "releases", -1) == 1 &&
                  zr_bool(&c.reply, "domain_stored") == 1 &&
                  zr_bool(&c.reply, "anchor_recorded") == 0;
        if (ok) {
            snprintf(root_hex, sizeof(root_hex), "%s", root);
            snprintf(script_hex, sizeof(script_hex), "%s", script);
            printf("OK\n");
        } else {
            printf("FAIL\n");
            failures++;
        }
        zr_cmd_free(&c);
    }

    uint8_t root[32];
    uint8_t script[128];
    size_t script_len = strlen(script_hex) / 2;
    struct zanc_message message;
    bool decoded = strlen(root_hex) == 64 && IsHex(root_hex) &&
        ParseHex(root_hex, root, sizeof(root)) == sizeof(root) &&
        script_len > 0 && script_len <= sizeof(script) && IsHex(script_hex) &&
        ParseHex(script_hex, script, sizeof(script)) == script_len &&
        zanc_parse(script, script_len, &message);
    printf("zcode_release simnet: exact command bytes bind root and label... ");
    if (decoded && message.hash_type == ZANC_HASH_SHA3_256 &&
        memcmp(message.digest, root, sizeof(root)) == 0 &&
        strcmp(message.label, "zcode@4242") == 0)
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    struct transaction_lab_simnet_receipt mined;
    bool mined_ok = decoded && transaction_lab_simnet_mine_op_return(
        script, script_len, &mined);
    printf("zcode_release simnet: exact ZANC transaction enters a block "
           "through connect_block... ");
    if (mined_ok && mined.mined_height >= 200 &&
        mined.transaction.num_vout == 2 && mined.change_zat == 800000)
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool db_open = node_db_open(&ndb, ":memory:");
    bool projected = db_open && mined_ok &&
        transaction_lab_simnet_project(&ndb, &mined);
    struct zanc_anchor anchor;
    memset(&anchor, 0, sizeof(anchor));
    bool found = projected && db_zanc_find_by_digest(
        &ndb, ZANC_HASH_SHA3_256, root, &anchor);
    printf("zcode_release simnet: mined bytes rebuild the ZANC projection... ");
    if (found && anchor.height == mined.mined_height &&
        memcmp(anchor.txid, mined.txid.data, sizeof(anchor.txid)) == 0 &&
        strcmp(anchor.label, "zcode@4242") == 0)
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    if (db_open)
        node_db_close(&ndb);
    if (mined_ok)
        transaction_lab_simnet_receipt_free(&mined);
    free(doc);
    zr_fixture_free(&f);
    return failures;
}

/* ── entry point ───────────────────────────────────────────────────── */

int test_zcode_release(void)
{
    int failures = 0;
    printf("\n=== zcode release command tests ===\n");

    node_rpc_client_set_test_hook(zr_rpc_stub);

    failures += test_zr_seed_perms();
    failures += test_zr_seed_hygiene();
    failures += test_zr_batch_determinism();
    failures += test_zr_batch_load();
    failures += test_zr_verify_errors();
    failures += test_zr_prove_verify();
    failures += test_zr_mined_anchor();

    node_rpc_client_set_test_hook(NULL);

    printf("=== ZCODE_RELEASE: %d failure(s) ===\n", failures);
    return failures;
}
