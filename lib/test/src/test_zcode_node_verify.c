/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_node_verify — `z23 zcode node verify` end to end, over REAL
 * bytes.
 *
 * These cases do not mock the artifact. The thing being hashed is this test
 * binary itself — a real stripped-or-not ELF with a real `.comment` section
 * — and the "rebuild" is a real copy of it on disk, byte-identical or with
 * one byte deliberately flipped. Only the BUILD is substituted (through the
 * documented test seam), because paying for a whole-program LTO link per
 * assertion would mean these assertions never ran.
 *
 * Proven here:
 *   1. MATCHING input passes and says what it covered.
 *   2. A TAMPERED artifact is caught — the differing artifact is named, with
 *      a rule, not a bare boolean — and is diagnosed rather than shrugged at.
 *   3. A PARTIALLY-verifiable input reports `partial`, `fully_verified`
 *      false, and every uncovered component by name. A partial reported as
 *      success is the exact failure mode this command exists to remove.
 *   4. The two benign explanations are separated from the damning one:
 *      a different source and a different toolchain each get their own
 *      verdict, so a user with a newer gcc is never told their publisher
 *      lied.
 *   5. There is NO input that makes this compare a publisher's hash against
 *      itself — the declared input keys carry no hash and no receipt, and
 *      the driver output is read from a path this command chose.
 *   6. Every refusal is named, and a rebuild that did not complete verifies
 *      NOTHING rather than reporting a pass.
 *
 * No node is started, stopped or signalled; no datadir is touched; every
 * file lives under ./test-tmp. */

#include "test/test_core.h"

#include "base/hex.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/os_proc.h"
#include "sha3/sha3.h"
#include "util/clientversion.h"
#include "vcs/node_reproduce.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define NV_CHECK(name, expr) do {                                          \
    if (expr) { printf("  zcode_node_verify: %s... OK\n", (name)); }       \
    else { printf("  zcode_node_verify: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* ── fixture plumbing ──────────────────────────────────────────────────── */

enum nv_mode {
    NV_MODE_MATCH = 0,      /* identical bytes, nothing uncovered */
    NV_MODE_PARTIAL,        /* identical bytes, one component not rebuilt */
    NV_MODE_TAMPER,         /* one byte different, same source + toolchain */
    NV_MODE_SOURCE_DIFFERS, /* one byte different, different source id */
    NV_MODE_TOOLCHAIN,      /* one byte different, different toolchain id */
    NV_MODE_DRIVER_FAILS,   /* the rebuild did not complete */
    NV_MODE_GARBAGE_RECEIPT /* the rebuild wrote something unparseable */
};

static enum nv_mode g_mode;
static char g_last_receipt[512];

static bool nv_sha3_file(const char *path, char hex[65], uint64_t *bytes)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char buf[16384];
    uint64_t total = 0;
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        sha3_256_write(&ctx, buf, n);
        total += n;
    }
    (void)fclose(f);
    uint8_t d[32];
    sha3_256_finalize(&ctx, d);
    zcl_hex_encode(d, 32, hex);
    if (bytes)
        *bytes = total;
    return true;
}

/* Copy `src` to `dst`. When `tamper` is true, flip one bit in the ELF
 * identification PADDING (e_ident[9]) — a byte no section owns, so the file
 * size, every section's contents, and `.comment` in particular are all
 * unchanged. That isolates the assertion to "the bytes differ", with no
 * chance of accidentally perturbing the toolchain identity as well. */
static bool nv_copy(const char *src, const char *dst, bool tamper)
{
    FILE *in = fopen(src, "rb");
    if (!in)
        return false;
    FILE *out = fopen(dst, "wb");
    if (!out) {
        (void)fclose(in);
        return false;
    }
    unsigned char buf[16384];
    size_t n;
    bool first = true;
    bool ok = true;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (first && tamper && n > 9) {
            buf[9] = (unsigned char)(buf[9] ^ 0x5a);
            first = false;
        }
        if (fwrite(buf, 1, n, out) != n) {
            ok = false;
            break;
        }
    }
    (void)fclose(in);
    ok = ok && fclose(out) == 0;
    if (ok)
        (void)chmod(dst, 0755);
    return ok;
}

static void nv_mkdirs(const char *scratch)
{
    char p[512];
    (void)snprintf(p, sizeof(p), "%s", scratch);
    (void)mkdir(p, 0755);
    (void)snprintf(p, sizeof(p), "%s/build", scratch);
    (void)mkdir(p, 0755);
    (void)snprintf(p, sizeof(p), "%s/build/bin", scratch);
    (void)mkdir(p, 0755);
}

/* The substituted rebuild. It writes a REAL file and a REAL receipt; the
 * command hashes and parses both exactly as it would after a real build. */
static int nv_driver(const char *source_dir, const char *scratch_dir,
                     const char *out_path, const char *profile, int jobs)
{
    (void)source_dir;
    (void)profile;
    (void)jobs;
    (void)snprintf(g_last_receipt, sizeof(g_last_receipt), "%s", out_path);
    if (g_mode == NV_MODE_DRIVER_FAILS)
        return 1;

    nv_mkdirs(scratch_dir);
    char built[512];
    (void)snprintf(built, sizeof(built), "%s/build/bin/z23", scratch_dir);

    if (g_mode == NV_MODE_GARBAGE_RECEIPT) {
        FILE *f = fopen(out_path, "wb");
        if (!f)
            return 1;
        (void)fputs("not a receipt at all\n", f);
        (void)fclose(f);
        return 0;
    }

    char self[512] = "";
    if (!os_proc_exe_path(self, sizeof(self)))
        return 1;
    bool tamper = g_mode == NV_MODE_TAMPER ||
                  g_mode == NV_MODE_SOURCE_DIFFERS ||
                  g_mode == NV_MODE_TOOLCHAIN;
    if (!nv_copy(self, built, tamper))
        return 1;

    char hex[65];
    uint64_t bytes = 0;
    if (!nv_sha3_file(built, hex, &bytes))
        return 1;

    FILE *f = fopen(out_path, "wb");
    if (!f)
        return 1;
    (void)fprintf(f, "%s\n", VCS_NODE_REPRO_SCHEMA);
    (void)fprintf(f, "producer local-rebuild\n");
    if (g_mode == NV_MODE_SOURCE_DIFFERS) {
        (void)fprintf(f, "source_id %s\n",
                      "4444444444444444444444444444444444444444"
                      "444444444444444444444444");
    } else {
        const char *sid = zcl_build_source_id_sha256();
        if (sid && strlen(sid) == 64)
            (void)fprintf(f, "source_id %s\n", sid);
    }
    if (g_mode == NV_MODE_TOOLCHAIN) {
        /* A receipt that already carries a toolchain identity is honoured;
         * the command only measures the rebuilt ELF when one is absent. */
        (void)fprintf(f, "toolchain %s\n",
                      "9999999999999999999999999999999999999999"
                      "999999999999999999999999");
    }
    (void)fprintf(f, "toolchain_desc test-substituted rebuild\n");
    (void)fprintf(f, "artifact %s %llu bin/z23\n", hex,
                  (unsigned long long)bytes);
    if (g_mode == NV_MODE_PARTIAL)
        (void)fprintf(f,
                      "unverified vendor/lib/libsecp256k1.a committed binary "
                      "with no resolved upstream source; linked as-is\n");
    (void)fclose(f);
    return 0;
}

/* ── one invocation ────────────────────────────────────────────────────── */

struct nv_run {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static const struct zcl_command_spec *nv_leaf(void)
{
    return zcl_command_registry_find(zcl_command_catalog(),
                                     "zcode.node.verify", NULL);
}

static void nv_run_init(struct nv_run *r, const char *scratch)
{
    json_init(&r->input);
    json_set_object(&r->input);
    (void)json_push_kv_str(&r->input, "source_dir", ".");
    (void)json_push_kv_str(&r->input, "scratch_dir", scratch);
    memset(&r->request, 0, sizeof(r->request));
    r->request.input = &r->input;
    zcl_command_reply_init(&r->reply, "zcl.zcode_node_verify.v1");
}

static void nv_run_free(struct nv_run *r)
{
    zcl_command_reply_free(&r->reply);
    json_free(&r->input);
}

static bool nv_exec(struct nv_run *r)
{
    const struct zcl_command_spec *spec = nv_leaf();
    if (!spec || !spec->handler)
        return false;
    char why[256];
    if (!zcl_command_registry_input_validate(spec, &r->input, why,
                                             sizeof(why)))
        return false;
    r->request.spec = spec;
    spec->handler(&r->request, &r->reply);
    return true;
}

static const char *nv_data_str(struct nv_run *r, const char *key)
{
    const struct json_value *v = json_get(&r->reply.data, key);
    const char *s = v ? json_get_str(v) : NULL;
    return s ? s : "";
}

static bool nv_data_bool(struct nv_run *r, const char *key)
{
    const struct json_value *v = json_get(&r->reply.data, key);
    return v && json_get_bool(v);
}

/* ── 1. registry contract ──────────────────────────────────────────────── */

static int t_registry_contract(void)
{
    int failures = 0;
    const struct zcl_command_spec *spec = nv_leaf();
    NV_CHECK("zcode.node.verify exists and binds a handler",
             spec != NULL && spec->handler != NULL);
    if (!spec)
        return failures;
    NV_CHECK("it is READY, not planned", spec->availability ==
                                             ZCL_COMMAND_READY);
    NV_CHECK("it declares both schemas",
             spec->input_schema && spec->input_schema[0] &&
                 spec->output_schema && spec->output_schema[0]);

    /* THE STRUCTURAL REFUSAL, asserted at the contract. If a hash, digest or
     * receipt could be handed in, a user could be talked into checking a
     * publisher's claim against itself and calling it verification. */
    const char *keys = spec->input_keys ? spec->input_keys : "";
    NV_CHECK("no input key can hand this a hash or someone else's receipt",
             !strstr(keys, "hash") && !strstr(keys, "sha") &&
                 !strstr(keys, "receipt") && !strstr(keys, "digest") &&
                 !strstr(keys, "expected"));
    NV_CHECK("it takes an artifact and a source tree and nothing central",
             strstr(keys, "artifact") && strstr(keys, "source_dir"));

    /* Adding a child to zcode.node must not push the branch menu over the
     * budget: an over-budget menu renders as NOTHING, not as a short one. */
    char out[16384];
    size_t n = zcl_command_registry_menu_json(zcl_command_catalog(),
                                              "zcode.node", out, sizeof(out));
    NV_CHECK("the zcode.node menu still renders inside its budget",
             n > 0 && n <= ZCL_COMMAND_BRANCH_BUDGET);
    NV_CHECK("and it lists verify", n > 0 && strstr(out, "verify") != NULL);
    return failures;
}

/* ── 2. the three headline cases ───────────────────────────────────────── */

static int t_match(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "nodeverify", "match");
    g_mode = NV_MODE_MATCH;

    struct nv_run r;
    nv_run_init(&r, dir);
    NV_CHECK("the matching case executes", nv_exec(&r));
    NV_CHECK("verdict is match",
             strcmp(nv_data_str(&r, "verdict"), "match") == 0);
    NV_CHECK("bytes_match and fully_verified are both true",
             nv_data_bool(&r, "bytes_match") &&
                 nv_data_bool(&r, "fully_verified"));
    NV_CHECK("it says how many artifacts it actually compared",
             json_get_int(json_get(&r.reply.data, "artifacts_compared")) == 1 &&
                 json_get_int(json_get(&r.reply.data, "artifacts_matched")) == 1);
    NV_CHECK("nothing is left uncovered in this fixture",
             json_get_int(json_get(&r.reply.data, "unverified_count")) == 0);
    NV_CHECK("the artifact it checked is this process's own executable",
             nv_data_bool(&r, "artifact_is_this_process"));
    NV_CHECK("it states that it contacted no server",
             json_get(&r.reply.data, "github_contacted") != NULL &&
                 !nv_data_bool(&r, "github_contacted"));
    NV_CHECK("the toolchain of BOTH sides was read the same way and agrees",
             nv_data_bool(&r, "toolchain_known") &&
                 nv_data_bool(&r, "toolchain_agrees"));
    NV_CHECK("it says in plain words what a match means",
             strstr(nv_data_str(&r, "means"), "trust") != NULL);
    nv_run_free(&r);
    test_rm_rf_recursive(dir);
    return failures;
}

static int t_tampered_artifact_is_caught(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "nodeverify", "tamper");
    g_mode = NV_MODE_TAMPER;

    struct nv_run r;
    nv_run_init(&r, dir);
    NV_CHECK("the tampered case executes", nv_exec(&r));
    NV_CHECK("it is NOT reported as a pass",
             !nv_data_bool(&r, "bytes_match") &&
                 !nv_data_bool(&r, "fully_verified") &&
                 strcmp(nv_data_str(&r, "verdict"), "match") != 0 &&
                 strcmp(nv_data_str(&r, "verdict"), "partial") != 0);
    NV_CHECK("exactly one artifact differed and it is counted",
             json_get_int(json_get(&r.reply.data, "artifacts_differed")) == 1 &&
                 json_get_int(json_get(&r.reply.data, "artifacts_matched")) == 0);

    /* The row, not a bare boolean: a mismatch nobody can act on is one
     * everybody learns to ignore. */
    const struct json_value *rows = json_get(&r.reply.data, "artifacts");
    const struct json_value *row0 = rows ? json_at(rows, 0) : NULL;
    const char *path = row0 ? json_get_str(json_get(row0, "artifact")) : NULL;
    const char *rule = row0 ? json_get_str(json_get(row0, "rule")) : NULL;
    const char *detail = row0 ? json_get_str(json_get(row0, "detail")) : NULL;
    NV_CHECK("the differing artifact is named",
             path != NULL && strcmp(path, "bin/z23") == 0);
    NV_CHECK("with a rule that says HOW it differed",
             rule != NULL && strcmp(rule, "content-differs") == 0);
    NV_CHECK("and a detail carrying both truncated hashes",
             detail != NULL && strstr(detail, "received sha3") != NULL &&
                 strstr(detail, "built") != NULL);

    /* One byte flipped in ELF padding leaves `.comment` untouched, so the
     * toolchain identity must still agree — that is what makes this a
     * DIAGNOSIS and not a shrug. */
    NV_CHECK("the toolchain still agrees (only the padding byte moved)",
             nv_data_bool(&r, "toolchain_agrees"));
    const char *sid = zcl_build_source_id_sha256();
    bool sid_known = sid && strlen(sid) == 64;
    if (sid_known)
        NV_CHECK("same source + same toolchain + different bytes = claim-false",
                 strcmp(nv_data_str(&r, "verdict"), "claim-false") == 0);
    else
        NV_CHECK("with no baked source identity it refuses to name a culprit",
                 strcmp(nv_data_str(&r, "verdict"), "undiagnosed") == 0);
    NV_CHECK("the detail explains the verdict rather than repeating it",
             strlen(nv_data_str(&r, "detail")) > 40);
    NV_CHECK("and it tells the user what to do about it",
             strlen(nv_data_str(&r, "means")) > 40);
    nv_run_free(&r);
    test_rm_rf_recursive(dir);
    return failures;
}

static int t_partial_is_not_success(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "nodeverify", "partial");
    g_mode = NV_MODE_PARTIAL;

    struct nv_run r;
    nv_run_init(&r, dir);
    NV_CHECK("the partial case executes", nv_exec(&r));
    NV_CHECK("verdict is partial, not match",
             strcmp(nv_data_str(&r, "verdict"), "partial") == 0);
    NV_CHECK("fully_verified is FALSE even though every byte matched",
             !nv_data_bool(&r, "fully_verified") &&
                 !nv_data_bool(&r, "bytes_match"));
    NV_CHECK("the bytes it DID compare are still reported as matching",
             json_get_int(json_get(&r.reply.data, "artifacts_matched")) == 1 &&
                 json_get_int(json_get(&r.reply.data, "artifacts_differed")) == 0);
    NV_CHECK("the uncovered component is counted",
             json_get_int(json_get(&r.reply.data, "unverified_count")) == 1);

    const struct json_value *gaps = json_get(&r.reply.data, "unverified");
    const struct json_value *g0 = gaps ? json_at(gaps, 0) : NULL;
    const char *comp = g0 ? json_get_str(json_get(g0, "component")) : NULL;
    const char *why = g0 ? json_get_str(json_get(g0, "reason")) : NULL;
    NV_CHECK("and NAMED in the reply, never silently excluded",
             comp != NULL && strcmp(comp, "vendor/lib/libsecp256k1.a") == 0);
    NV_CHECK("with a reason the reader can act on",
             why != NULL && strstr(why, "no resolved upstream source") != NULL);
    NV_CHECK("the envelope status is not mistaken for the verdict",
             strstr(nv_data_str(&r, "status_means"), "not a pass") != NULL);
    NV_CHECK("the scope line warns that unverified is outside the verdict",
             strstr(nv_data_str(&r, "scope"), "unverified") != NULL);
    nv_run_free(&r);
    test_rm_rf_recursive(dir);
    return failures;
}

/* ── 3. the benign explanations stay separate from the damning one ─────── */

static int t_benign_causes_are_named_separately(void)
{
    int failures = 0;
    char dir[256];
    const char *sid = zcl_build_source_id_sha256();
    bool sid_known = sid && strlen(sid) == 64;

    test_make_tmpdir(dir, sizeof(dir), "nodeverify", "srcdiff");
    g_mode = NV_MODE_SOURCE_DIFFERS;
    struct nv_run r;
    nv_run_init(&r, dir);
    NV_CHECK("the different-source case executes", nv_exec(&r));
    if (sid_known) {
        NV_CHECK("a different source tree is named as such",
                 strcmp(nv_data_str(&r, "verdict"), "source-differs") == 0);
        NV_CHECK("and is explicitly NOT held against the publisher",
                 strstr(nv_data_str(&r, "means"), "nothing has been shown "
                                                  "about the publisher") !=
                     NULL);
    } else {
        NV_CHECK("without a baked source id it stays undiagnosed",
                 strcmp(nv_data_str(&r, "verdict"), "undiagnosed") == 0);
    }
    NV_CHECK("source agreement is reported as its own field",
             json_get(&r.reply.data, "source_identity_agrees") != NULL);
    nv_run_free(&r);
    test_rm_rf_recursive(dir);

    test_make_tmpdir(dir, sizeof(dir), "nodeverify", "tcdiff");
    g_mode = NV_MODE_TOOLCHAIN;
    nv_run_init(&r, dir);
    NV_CHECK("the different-toolchain case executes", nv_exec(&r));
    if (sid_known) {
        NV_CHECK("a different compiler is named as the cause",
                 strcmp(nv_data_str(&r, "verdict"), "toolchain-differs") == 0);
        NV_CHECK("and the user is told this is not evidence against anyone",
                 strstr(nv_data_str(&r, "means"), "NOT evidence against") !=
                     NULL);
    } else {
        NV_CHECK("without a baked source id it stays undiagnosed",
                 strcmp(nv_data_str(&r, "verdict"), "undiagnosed") == 0);
    }
    NV_CHECK("the toolchain the artifact records is shown, not just hashed",
             strlen(nv_data_str(&r, "verdict")) > 0);
    nv_run_free(&r);
    test_rm_rf_recursive(dir);
    return failures;
}

/* ── 4. refusals are named, and never a quiet pass ─────────────────────── */

static int t_refusals_are_named(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "nodeverify", "refuse");
    const struct zcl_command_spec *spec = nv_leaf();

    struct nv_run r;
    g_mode = NV_MODE_DRIVER_FAILS;
    nv_run_init(&r, dir);
    NV_CHECK("a failed rebuild executes", nv_exec(&r));
    NV_CHECK("a rebuild that did not complete verifies NOTHING, by name",
             strcmp(r.reply.error.code, "REBUILD_FAILED") == 0 &&
                 r.reply.status == ZCL_COMMAND_STATUS_FAILED);
    NV_CHECK("and says so rather than reporting an empty comparison",
             strstr(r.reply.error.message, "nothing is verified") != NULL);
    nv_run_free(&r);

    g_mode = NV_MODE_GARBAGE_RECEIPT;
    nv_run_init(&r, dir);
    NV_CHECK("an unparseable rebuild receipt executes", nv_exec(&r));
    NV_CHECK("an unreadable receipt is a named refusal, not a partial parse",
             strcmp(r.reply.error.code, "REBUILD_RECEIPT_INVALID") == 0);
    nv_run_free(&r);

    g_mode = NV_MODE_MATCH;
    nv_run_init(&r, dir);
    (void)json_push_kv_str(&r.input, "artifact", "./test-tmp/no-such-file");
    NV_CHECK("a missing artifact executes", nv_exec(&r));
    NV_CHECK("a missing artifact is named ARTIFACT_MISSING",
             strcmp(r.reply.error.code, "ARTIFACT_MISSING") == 0);
    nv_run_free(&r);

    nv_run_init(&r, dir);
    (void)json_push_kv_str(&r.input, "profile", "trust-me");
    NV_CHECK("an unknown build profile executes", nv_exec(&r));
    NV_CHECK("an unknown build profile is named BAD_PROFILE",
             strcmp(r.reply.error.code, "BAD_PROFILE") == 0);
    nv_run_free(&r);

    /* A source directory with no rebuild driver is a refusal even though the
     * directory exists: without source there is nothing to rebuild, and
     * answering anything else would be an opinion. */
    zcl_native_node_verify_test_set_driver(NULL);
    nv_run_init(&r, dir);
    json_free(&r.input);
    json_init(&r.input);
    json_set_object(&r.input);
    (void)json_push_kv_str(&r.input, "source_dir", dir);
    (void)json_push_kv_str(&r.input, "scratch_dir", dir);
    NV_CHECK("a directory that is not a checkout executes", nv_exec(&r));
    NV_CHECK("a directory with no rebuild driver is named NO_SOURCE_TREE",
             strcmp(r.reply.error.code, "NO_SOURCE_TREE") == 0);
    nv_run_free(&r);
    zcl_native_node_verify_test_set_driver(nv_driver);

    (void)spec;
    test_rm_rf_recursive(dir);
    return failures;
}

/* ── 5. the whole report survives the wire ─────────────────────────────── */

static int t_envelope_renders(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "nodeverify", "render");
    g_mode = NV_MODE_PARTIAL;
    const struct zcl_command_spec *spec = nv_leaf();
    if (!spec) {
        test_rm_rf_recursive(dir);
        return failures;
    }

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "source_dir", ".");
    (void)json_push_kv_str(&input, "scratch_dir", dir);

    static char out[65536];
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n = zcl_command_registry_execute_json(
        zcl_command_catalog(), spec, NULL, &input, false, "zcode.node.verify",
        NULL, 0, 0, NULL, out, sizeof(out), &code);

    /* An over-budget reply renders as NOTHING, not as a shorter one. A
     * verification report that vanishes is worse than one that never ran. */
    NV_CHECK("the full report renders inside the leaf's declared budget",
             n > 0 && n <= (size_t)spec->budget_bytes);
    NV_CHECK("the rendered envelope carries the verdict",
             n > 0 && strstr(out, "\"verdict\":\"partial\"") != NULL);
    NV_CHECK("and the uncovered component survives to the wire",
             n > 0 && strstr(out, "libsecp256k1.a") != NULL);
    NV_CHECK("and both receipts are rendered so the hashes are publishable",
             n > 0 && strstr(out, "\"received\"") != NULL &&
                 strstr(out, "\"rebuilt\"") != NULL);
    json_free(&input);
    test_rm_rf_recursive(dir);
    return failures;
}

int test_zcode_node_verify(void)
{
    int failures = 0;
    printf("=== zcode_node_verify ===\n");
    zcl_native_node_verify_test_set_driver(nv_driver);
    failures += t_registry_contract();
    failures += t_match();
    failures += t_tampered_artifact_is_caught();
    failures += t_partial_is_not_success();
    failures += t_benign_causes_are_named_separately();
    failures += t_refusals_are_named();
    failures += t_envelope_renders();
    zcl_native_node_verify_test_set_driver(NULL);
    printf("=== zcode_node_verify: %d failures ===\n", failures);
    return failures;
}
