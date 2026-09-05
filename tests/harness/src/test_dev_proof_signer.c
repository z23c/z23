/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_dev_proof_signer — adversarial proof that a push-proof receipt now
 * carries an identity, and that admission trusts that identity instead of a
 * digest anybody with write access could recompute.
 *
 * Before this group's subject existed, a receipt was sealed with a keyless
 * SHA3-256 digest over its own bytes. Every negative below therefore has to
 * be one the OLD code passed: a receipt whose fields were edited and whose
 * seal was recomputed admitted; a receipt written by any other process on the
 * box admitted; a receipt from another host could neither be attributed nor
 * refused by name. Each TEST states which of those it kills.
 *
 * Every fixture lives under test-tmp/ with XDG_STATE_HOME redirected into it,
 * so no assertion here reads or writes the operator's real signing key. */

#include "test/test_core.h"

#include "base/hex.h"
#include "crypto/ed25519.h"
#include "dev_proof_receipt.h"
#include "dev_proof_signer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#include <unistd.h>
#endif

#define DPS_LOCAL "1111111111111111111111111111111111111111"
#define DPS_BASE "2222222222222222222222222222222222222222"
/* Repeated verbatim from dev_proof_receipt.c on purpose: a test that asks
 * the subject for its own domain string cannot notice the string changing. */
#define DPS_SIGN_DOMAIN "zcl.dev_proof_receipt.v2"
#define DPS_SIGN_DOMAIN_BYTES (sizeof(DPS_SIGN_DOMAIN) - 1u)
#define DPS_SIGN_MESSAGE_BYTES \
    (DPS_SIGN_DOMAIN_BYTES + ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES)
/* Offset of the u32 format version inside the record: 8 magic bytes. */
#define DPS_VERSION_OFFSET 8u

static char g_dps_state[PATH_MAX];
static char g_dps_saved_xdg[PATH_MAX];
static bool g_dps_had_xdg;

/* Point the state-root resolver at this group's own tree. Called per TEST so
 * that a case which wants a virgin box (no key, no allowlist) can have one. */
static void dps_isolate(const char *tag)
{
    char base[PATH_MAX - 64];
    test_make_tmpdir(base, sizeof(base), "dev_proof_signer", tag);
    (void)snprintf(g_dps_state, sizeof(g_dps_state), "%s/state", base);
    if (!g_dps_had_xdg && getenv("XDG_STATE_HOME")) {
        g_dps_had_xdg = true;
        (void)snprintf(g_dps_saved_xdg, sizeof(g_dps_saved_xdg), "%s",
                       getenv("XDG_STATE_HOME"));
    }
    setenv("XDG_STATE_HOME", g_dps_state, 1);
}

static void dps_restore(void)
{
    if (g_dps_had_xdg)
        setenv("XDG_STATE_HOME", g_dps_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
}

/* A structurally complete receipt with no dimensions selected: every fixed
 * root non-zero, every dimension trivially complete, so nothing but the
 * signature decides admission. */
static struct zcl_dev_acceptance_receipt_v1 dps_receipt(void)
{
    struct zcl_dev_acceptance_receipt_v1 receipt = {0};
    (void)zcl_dev_proof_oid_decode(DPS_LOCAL, receipt.local_commit,
                                   &receipt.local_commit_len);
    (void)zcl_dev_proof_oid_decode(DPS_BASE, receipt.remote_base,
                                   &receipt.remote_base_len);
    uint8_t *roots[] = {
        receipt.source_root, receipt.source_cas_root, receipt.mutation_root,
        receipt.changed_set_root, receipt.impact_policy_root,
        receipt.compiler_root, receipt.flags_root, receipt.environment_root,
        receipt.build_graph_root, receipt.child_set_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        memset(roots[i], (int)i + 1, ZCL_DEV_PROOF_ROOT_BYTES);
    receipt.policy_version = 1;
    receipt.complete = 1;
    receipt.created_unix = 1757030400u;
    receipt.elapsed_ms = 1234u;
    (void)zcl_dev_proof_receipt_child_set_root(&receipt,
                                               receipt.child_set_root);
    return receipt;
}

static bool dps_sealed(struct zcl_dev_acceptance_receipt_v1 *out)
{
    *out = dps_receipt();
    return zcl_dev_proof_receipt_seal(out);
}

static bool dps_validate(const struct zcl_dev_acceptance_receipt_v1 *receipt,
                         char *why, size_t why_len)
{
    return zcl_dev_proof_receipt_validate(receipt, DPS_LOCAL, DPS_BASE, why,
                                          why_len);
}

/* Re-sign an already-serialized record with a caller-supplied key, exactly
 * the way a hostile producer on another box would. */
static void dps_resign(uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES],
                       const uint8_t seed[32])
{
    uint8_t message[DPS_SIGN_MESSAGE_BYTES];
    uint8_t pubkey[32], secret[32], signature[64];
    ed25519_keypair(pubkey, secret, seed);
    memcpy(message, DPS_SIGN_DOMAIN, DPS_SIGN_DOMAIN_BYTES);
    memcpy(message + DPS_SIGN_DOMAIN_BYTES, wire,
           ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES);
    ed25519_sign(signature, message, sizeof(message), seed, pubkey);
    memcpy(wire + ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES, pubkey, sizeof(pubkey));
    memcpy(wire + ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES + sizeof(pubkey),
           signature, sizeof(signature));
}

static bool dps_write(const char *path, const void *data, size_t len,
                      unsigned mode)
{
    FILE *f = fopen(path, "wb");
    bool ok = f && (len == 0 || fwrite(data, 1, len, f) == len);
    if (f) ok = fclose(f) == 0 && ok;
#if !defined(_WIN32)
    if (ok) ok = chmod(path, (mode_t)mode) == 0;
#else
    (void)mode;
#endif
    return ok;
}

static bool dps_allow_path(char *out, size_t cap)
{
    return zcl_dev_proof_signer_paths(NULL, 0, out, cap);
}

static bool dps_key_path(char *out, size_t cap)
{
    return zcl_dev_proof_signer_paths(out, cap, NULL, 0);
}

/* ── 1. round trip ──────────────────────────────────────────────────────── */

static int test_dps_round_trip(void)
{
    int failures = 0;
    struct zcl_dev_acceptance_receipt_v1 receipt, parsed;
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    uint8_t own[32];
    bool present = false;
    const char *why_token = NULL;
    char why[128];
    TEST("dev proof signer: a receipt this box signed round trips and is "
         "admitted without being listed anywhere") {
        dps_isolate("round_trip");
        ASSERT(dps_sealed(&receipt));
        ASSERT(receipt.has_signature);
        ASSERT(zcl_dev_proof_receipt_serialize(&receipt, wire));
        /* The v1 body is byte-identical to what v1 wrote; only the trailer
         * and the version stamp are new. */
        ASSERT(sizeof(wire) == ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES + 96u);
        ASSERT(wire[DPS_VERSION_OFFSET] == 2u);
        ASSERT(zcl_dev_proof_receipt_parse(wire, sizeof(wire), &parsed));
        ASSERT(parsed.has_signature);
        ASSERT(memcmp(parsed.signer_pubkey, receipt.signer_pubkey, 32) == 0);
        ASSERT(memcmp(parsed.signature, receipt.signature, 64) == 0);
        ASSERT(dps_validate(&parsed, why, sizeof(why)));
        ASSERT(why[0] == 0);
        /* Own key is trusted with no allowlist on disk at all. */
        struct zcl_dev_proof_allowlist_state state;
        ASSERT(zcl_dev_proof_signer_allowlist_state(&state, &why_token));
        ASSERT(!state.present);
        ASSERT(state.trusted == 0 && state.malformed == 0);
        ASSERT(!state.self_listed);
        ASSERT(zcl_dev_proof_signer_public(own, &present, &why_token));
        ASSERT(present);
        ASSERT(memcmp(own, receipt.signer_pubkey, 32) == 0);
        dps_restore();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. one flipped byte ────────────────────────────────────────────────── */

static int test_dps_flipped_byte(void)
{
    int failures = 0;
    struct zcl_dev_acceptance_receipt_v1 receipt, parsed;
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    char why[128];
    /* One byte inside each field the old keyless seal let an editor rewrite:
     * a root, a dimension count, the timestamp, the completeness flag, and
     * the stored seal itself. The old code accepted every one of these once
     * the seal was recomputed. */
    static const size_t offsets[] = {80u, 300u, 560u, 620u, 640u};
    TEST("dev proof signer: any edited byte in a signed record is refused "
         "as signature_invalid, recomputed seal or not") {
        dps_isolate("flipped_byte");
        ASSERT(dps_sealed(&receipt));
        for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
            ASSERT(zcl_dev_proof_receipt_serialize(&receipt, wire));
            ASSERT(offsets[i] < ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES);
            wire[offsets[i]] ^= 1u;
            ASSERT(zcl_dev_proof_receipt_parse(wire, sizeof(wire), &parsed));
            ASSERT(!dps_validate(&parsed, why, sizeof(why)));
            ASSERT(strcmp(why, "signature_invalid") == 0);
        }
        /* And a flipped signature byte is the same verdict. */
        ASSERT(zcl_dev_proof_receipt_serialize(&receipt, wire));
        wire[ZCL_DEV_PROOF_WIRE_BYTES - 1u] ^= 1u;
        ASSERT(zcl_dev_proof_receipt_parse(wire, sizeof(wire), &parsed));
        ASSERT(!dps_validate(&parsed, why, sizeof(why)));
        ASSERT(strcmp(why, "signature_invalid") == 0);
        /* An edit to the commit identity is named as the mismatch it is,
         * because that check is more useful to the operator than "forged". */
        parsed = receipt;
        parsed.local_commit[0] ^= 1u;
        ASSERT(!dps_validate(&parsed, why, sizeof(why)));
        ASSERT(strcmp(why, "receipt_commit_or_base_mismatch") == 0);
        dps_restore();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. an unsigned (v1) record ─────────────────────────────────────────── */

static int test_dps_unsigned_record(void)
{
    int failures = 0;
    struct zcl_dev_acceptance_receipt_v1 receipt, parsed;
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    char why[128];
    TEST("dev proof signer: the v1 record every cache still holds is parsed "
         "and refused as receipt_unsigned") {
        dps_isolate("unsigned_record");
        ASSERT(dps_sealed(&receipt));
        ASSERT(zcl_dev_proof_receipt_serialize(&receipt, wire));
        /* Exactly what a pre-change cache file is: the same 664 bytes with
         * the version stamped 1 and no trailer. */
        wire[DPS_VERSION_OFFSET] = 1u;
        ASSERT(zcl_dev_proof_receipt_parse(
            wire, ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES, &parsed));
        ASSERT(!parsed.has_signature);
        ASSERT(!dps_validate(&parsed, why, sizeof(why)));
        ASSERT(strcmp(why, "receipt_unsigned") == 0);
        /* An unsigned receipt cannot even be written back out, so nothing
         * downstream can re-publish one by accident. */
        ASSERT(!zcl_dev_proof_receipt_serialize(&parsed, wire));
        /* A v1 body wearing the v2 length, or the reverse, is not a record. */
        ASSERT(!zcl_dev_proof_receipt_parse(
            wire, ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES - 1u, &parsed));
        dps_restore();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4 & 5. unknown signer, then the same key trusted ───────────────────── */

static int test_dps_allowlist(void)
{
    int failures = 0;
    struct zcl_dev_acceptance_receipt_v1 receipt, parsed;
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    uint8_t seed[32], pubkey[32], secret[32];
    char allow[PATH_MAX], line[160], hex[65], why[128];
    const char *why_token = NULL;
    TEST("dev proof signer: another box's receipt is signer_unknown until "
         "its key is in signers.allow, then it is admitted") {
        dps_isolate("allowlist");
        memset(seed, 0xA5, sizeof(seed));
        ed25519_keypair(pubkey, secret, seed);
        zcl_hex_encode(pubkey, sizeof(pubkey), hex);
        ASSERT(dps_sealed(&receipt));
        ASSERT(zcl_dev_proof_receipt_serialize(&receipt, wire));
        dps_resign(wire, seed);
        ASSERT(zcl_dev_proof_receipt_parse(wire, sizeof(wire), &parsed));
        ASSERT(memcmp(parsed.signer_pubkey, pubkey, sizeof(pubkey)) == 0);
        ASSERT(!dps_validate(&parsed, why, sizeof(why)));
        ASSERT(strcmp(why, "signer_unknown") == 0);

        ASSERT(dps_allow_path(allow, sizeof(allow)));
        /* Malformed and commented lines are counted and skipped, and the
         * trusted key is the LAST line with no trailing newline — the shape
         * a hand-edit or an `echo -n >>` actually produces. */
        int n = snprintf(line, sizeof(line),
                         "# boxes that may push here\n"
                         "\n"
                         "   not-a-key\n"
                         "%s", hex);
        ASSERT(n > 0 && (size_t)n < sizeof(line));
        ASSERT(dps_write(allow, line, (size_t)n, 0600));
        ASSERT(dps_validate(&parsed, why, sizeof(why)));

        struct zcl_dev_proof_allowlist_state state;
        ASSERT(zcl_dev_proof_signer_allowlist_state(&state, &why_token));
        ASSERT(state.present);
        ASSERT(state.trusted == 1);
        ASSERT(state.malformed == 1);
        ASSERT(!state.self_listed);

        /* Trust is per key, not per file: a different foreign key is still
         * unknown while that file is on disk. */
        memset(seed, 0x5A, sizeof(seed));
        ASSERT(zcl_dev_proof_receipt_serialize(&receipt, wire));
        dps_resign(wire, seed);
        ASSERT(zcl_dev_proof_receipt_parse(wire, sizeof(wire), &parsed));
        ASSERT(!dps_validate(&parsed, why, sizeof(why)));
        ASSERT(strcmp(why, "signer_unknown") == 0);
        dps_restore();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6. an unreadable key ───────────────────────────────────────────────── */

static int test_dps_key_unreadable(void)
{
    int failures = 0;
    struct zcl_dev_acceptance_receipt_v1 receipt;
    uint8_t junk[31] = {0};
    char key[PATH_MAX], why[128];
    TEST("dev proof signer: a key file that is not a private 32-byte seed "
         "fails sealing by name instead of producing an unsigned receipt") {
        dps_isolate("key_unreadable");
        ASSERT(dps_key_path(key, sizeof(key)));
        ASSERT(dps_write(key, junk, sizeof(junk), 0600));
        receipt = dps_receipt();
        ASSERT(!zcl_dev_proof_receipt_seal(&receipt));
        ASSERT(!receipt.has_signature);
        /* And the refusal is visible to a verifier too. */
        uint8_t pubkey[32], signature[64];
        const char *why_token = NULL;
        ASSERT(!zcl_dev_proof_signer_sign((const uint8_t *)"x", 1u, pubkey,
                                          signature, &why_token));
        ASSERT(why_token && strcmp(why_token, "signer_key_unreadable") == 0);
        bool present = true;
        why_token = NULL;
        ASSERT(!zcl_dev_proof_signer_public(pubkey, &present, &why_token));
        ASSERT(why_token && strcmp(why_token, "signer_key_unreadable") == 0);
        why_token = NULL;
        ASSERT(!zcl_dev_proof_signer_verify((const uint8_t *)"x", 1u, pubkey,
                                            signature, &why_token));
        ASSERT(why_token && strcmp(why_token, "signer_key_unreadable") == 0);
        (void)why;
        dps_restore();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 7. the hook's own admit path ───────────────────────────────────────── */

#if !defined(_WIN32)
static int dps_run(const char *cwd, const char *const argv[],
                   const char *stdin_text, char *out, size_t out_size)
{
    int pipe_in[2], pipe_out[2];
    if (pipe(pipe_in) != 0) return -1;
    if (pipe(pipe_out) != 0) {
        (void)close(pipe_in[0]);
        (void)close(pipe_in[1]);
        return -1;
    }
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        (void)dup2(pipe_in[0], STDIN_FILENO);
        (void)dup2(pipe_out[1], STDOUT_FILENO);
        (void)dup2(pipe_out[1], STDERR_FILENO);
        (void)close(pipe_in[0]);
        (void)close(pipe_in[1]);
        (void)close(pipe_out[0]);
        (void)close(pipe_out[1]);
        if (cwd && chdir(cwd) != 0) _exit(127);
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    (void)close(pipe_in[0]);
    (void)close(pipe_out[1]);
    size_t len = stdin_text ? strlen(stdin_text) : 0;
    if (len) (void)!write(pipe_in[1], stdin_text, len);
    (void)close(pipe_in[1]);
    size_t used = 0;
    for (;;) {
        if (used + 1 >= out_size) break;
        ssize_t got = read(pipe_out[0], out + used, out_size - used - 1);
        if (got <= 0) break;
        used += (size_t)got;
    }
    out[used] = 0;
    (void)close(pipe_out[0]);
    int status = 0;
    while (waitpid(child, &status, 0) < 0)
        ;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Build a two-commit repository whose HEAD and HEAD~1 are the exact pair the
 * hook is asked to admit, so admit_pair() reaches its receipt read instead of
 * stopping at the ancestry check. */
static bool dps_git_rig(const char *dir, char *local, char *base)
{
    char cmd[PATH_MAX * 2];
    int n = snprintf(cmd, sizeof(cmd),
                     "cd '%s' && git init -q -b main . && "
                     "git config user.email z@z && git config user.name z && "
                     "git config commit.gpgsign false && "
                     "git config core.hooksPath '%s/nohooks' && "
                     "echo a > a.txt && git add a.txt && "
                     "git commit -q -m a && "
                     "echo b >> a.txt && git add a.txt && "
                     "git commit -q -m b && "
                     "git rev-parse HEAD > head.txt && "
                     "git rev-parse HEAD~1 > base.txt", dir, dir);
    if (n <= 0 || (size_t)n >= sizeof(cmd) || system(cmd) != 0)
        return false;
    for (int which = 0; which < 2; which++) {
        char path[PATH_MAX];
        char *out = which ? base : local;
        n = snprintf(path, sizeof(path), "%s/%s", dir,
                     which ? "base.txt" : "head.txt");
        if (n <= 0 || (size_t)n >= sizeof(path)) return false;
        FILE *f = fopen(path, "r");
        if (!f) return false;
        bool ok = fgets(out, 65, f) != NULL;
        (void)fclose(f);
        size_t len = ok ? strlen(out) : 0;
        while (len && (out[len - 1] == '\n' || out[len - 1] == '\r'))
            out[--len] = 0;
        if (!ok || len != 40) return false;
    }
    return true;
}

static bool dps_put_receipt(const char *dir, const char *local,
                            const char *base, const void *wire, size_t len)
{
    char cmd[PATH_MAX], path[PATH_MAX];
    int n = snprintf(cmd, sizeof(cmd),
                     "mkdir -p '%s/.cache/zcl-dev-proof/receipts'", dir);
    if (n <= 0 || (size_t)n >= sizeof(cmd) || system(cmd) != 0)
        return false;
    n = snprintf(path, sizeof(path),
                 "%s/.cache/zcl-dev-proof/receipts/%s-%s.receipt", dir, local,
                 base);
    return n > 0 && (size_t)n < sizeof(path) &&
           dps_write(path, wire, len, 0600);
}

static int test_dps_hook_admission(void)
{
    int failures = 0;
    struct zcl_dev_acceptance_receipt_v1 receipt;
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    uint8_t seed[32];
    char dir[PATH_MAX - 64], hook[PATH_MAX], local[65], base[65];
    char out[4096], tuple[256];
    TEST("dev proof signer: the installed pre-push hook refuses a forged and "
         "an unsigned receipt, and admits only the one this box signed") {
        dps_isolate("hook_admission");
        test_make_tmpdir(dir, sizeof(dir), "dev_proof_signer", "hook_repo");
        ASSERT(test_abs_path("build/bin/z23-git-hook", hook, sizeof(hook)));
        /* Not a skip: `make install-hooks` is mandatory in every worktree, so
         * a missing hook binary is a broken checkout, not an excused case. */
        ASSERT(access(hook, X_OK) == 0);
        ASSERT(dps_git_rig(dir, local, base));
        int n = snprintf(tuple, sizeof(tuple),
                         "refs/heads/main %s refs/heads/main %s\n", local,
                         base);
        ASSERT(n > 0 && (size_t)n < sizeof(tuple));
        const char *argv[] = {hook, "--hook=pre-push", "origin", "origin",
                              NULL};

        /* A receipt for this exact pair, signed by a key this box does not
         * trust — the forgery the old keyless seal could not tell from real. */
        receipt = dps_receipt();
        (void)zcl_dev_proof_oid_decode(local, receipt.local_commit,
                                       &receipt.local_commit_len);
        (void)zcl_dev_proof_oid_decode(base, receipt.remote_base,
                                       &receipt.remote_base_len);
        ASSERT(zcl_dev_proof_receipt_seal(&receipt));
        ASSERT(zcl_dev_proof_receipt_serialize(&receipt, wire));
        memset(seed, 0x33, sizeof(seed));
        dps_resign(wire, seed);
        ASSERT(dps_put_receipt(dir, local, base, wire, sizeof(wire)));
        ASSERT(dps_run(dir, argv, tuple, out, sizeof(out)) != 0);
        ASSERT(strstr(out, "status=signer_unknown") != NULL);

        /* The same record with the version stamped back to 1 and the trailer
         * cut off: exactly a cache file written before this change. */
        ASSERT(zcl_dev_proof_receipt_serialize(&receipt, wire));
        wire[DPS_VERSION_OFFSET] = 1u;
        ASSERT(dps_put_receipt(dir, local, base, wire,
                               ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES));
        ASSERT(dps_run(dir, argv, tuple, out, sizeof(out)) != 0);
        ASSERT(strstr(out, "status=receipt_unsigned") != NULL);

        /* And the genuine article passes, so the refusals above are the
         * signature talking and not the fixture being wrong. */
        ASSERT(zcl_dev_proof_receipt_serialize(&receipt, wire));
        ASSERT(dps_put_receipt(dir, local, base, wire, sizeof(wire)));
        ASSERT(dps_run(dir, argv, tuple, out, sizeof(out)) == 0);
        ASSERT(strstr(out, "PASS exact local receipt admitted") != NULL);
        dps_restore();
        PASS();
    } _test_next:;
    return failures;
}
#endif

int test_dev_proof_signer(void)
{
    int failures = 0;
    failures += test_dps_round_trip();
    failures += test_dps_flipped_byte();
    failures += test_dps_unsigned_record();
    failures += test_dps_allowlist();
    failures += test_dps_key_unreadable();
#if !defined(_WIN32)
    failures += test_dps_hook_admission();
#endif
    dps_restore();
    return failures;
}
