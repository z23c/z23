/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land.check_offer / attest_offer / verify_offer_receipt / reverify_offer:
 * the offer manifest, the signed receipt and the re-verification of an offered
 * commit. check_offer onward were moved out of native_dev_land_remote.c
 * (which keeps send and receive).
 *
 * check_offer (any machine, read-only) takes --bundle and --offer (absolute
 *          paths) and optional --repo (default: the checkout above the
 *          current directory). It queues nothing, fetches nothing and
 *          touches no worktree. Refusals: OFFER_BAD_MANIFEST (wrong schema,
 *          malformed commit, base or sha), OFFER_SHA_MISMATCH (the bundle's
 *          sha256 is not the offered one), OFFER_BAD_BUNDLE (git bundle
 *          verify failed in --repo), OFFER_HEAD_MISMATCH (not exactly one
 *          head, equal to the offered commit), OFFER_BASE_MISMATCH (not
 *          exactly one prerequisite, equal to the offered base). Reply:
 *          data {commit, base, bundle_sha256, verdict "ok"}.
 * attest_offer (the receiver) takes check_offer's inputs plus an absolute
 *          --receipt_out. It runs exactly check_offer's checks and only on a
 *          pass writes a receipt {schema "zcl.dev_land_offer_receipt.v1",
 *          commit, base, bundle_sha256, checks "bundle_sha256,bundle_verify,
 *          head,base", verdict "ok", signer (64 hex), signature (128 hex)}.
 *          The Ed25519 signature, by this box's dev_proof_signer key, covers
 *          "<schema>\n" commit "\n" base "\n" bundle_sha256 "\n" checks "\n"
 *          verdict "\n". A failed check writes nothing and returns
 *          check_offer's code; OFFER_RECEIPT_EXISTS when receipt_out exists
 *          (never replaced); OFFER_RECEIPT_FAILED when signing or writing
 *          fails. Reply: check_offer's data plus receipt and signer.
 * verify_offer_receipt (read-only) takes --receipt and optional --offer.
 *          OFFER_RECEIPT_BAD (not a v1 receipt), RECEIPT_SIGNATURE_INVALID
 *          (the bytes do not verify), RECEIPT_SIGNER_UNKNOWN (neither this
 *          box's key nor on its signers.allow), RECEIPT_OFFER_MISMATCH (with
 *          --offer: another commit, base or bundle_sha256). Reply: data
 *          {commit, base, signer, verdict, checks}.
 * reverify_offer (the receiver) takes check_offer's inputs plus an optional
 *          absolute --receipt_out. It runs check_offer's checks, fetches the
 *          bundle head into refs/z23-reverify/<sha12>, adds a detached
 *          scratch worktree at the offered base under a private temp
 *          directory and `git cherry-pick --no-commit`s the commit into it
 *          (REVERIFY_APPLY on a conflict). The unit is the one changed .c
 *          (REVERIFY_NOT_A_SPLIT unless the commit changes exactly one .c,
 *          plus optionally the complexity baseline, and deletes baseline
 *          rows of that file) and the functions of those rows. The baseline
 *          is put back to the base (dev cx check applies its own tighten),
 *          the repo's build/bin/z23-lint is copied in and
 *          `dev cx check --worktree --file --functions` runs as a child: the
 *          running binary, or in ZCL_TESTING builds the program named by
 *          ZCL_LAND_REVERIFY_CX. Anything but a pass is REVERIFY_CX_FAILED
 *          (the child's exit, code and detail as evidence); REVERIFY_SETUP
 *          when the fetch, worktree or lint copy fails. The scratch worktree
 *          and the temporary ref are removed on every path. With
 *          receipt_out a pass is signed like attest_offer's with checks
 *          "bundle_sha256,bundle_verify,head,base,cx_check". Reply: data
 *          {commit, base, file, functions, verdict, receipt?}.
 */

#include "command/native_command.h"
#include "command/native_dev_land_precheck.h"
#include "command/native_dev_land_remote_shared.h"
#include "command/native_devagent.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/path_compat.h"
#include "platform/os_proc.h"
#include "platform/private_directory.h"
#include "platform/temp_directory.h"
#include "util/spawn.h"
#include "crypto/sha256.h"
#include "dev_proof_signer.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define DLR_MS (10 * 60 * 1000)

/* ── check_offer ───────────────────────────────────────────────────────── */

#define DLR_OFFER_SCHEMA "zcl.dev_land_offer.v1"
#define DLR_OFFER_MAX 4096u

struct dlr_offer {
    struct dlr_recv r;
    char commit[48], base[48], bsha[80], lane[64], prereq[48];
    const char *leaf; /* the leaf whose reply carries a refusal */
};

static void dlr_offer_fail(const char *leaf, struct zcl_command_reply *reply,
                           const char *code, const char *phase,
                           const char *msg, const char *evidence)
{
    zcl_dlr_fail(reply, leaf, code, phase, msg, evidence);
}

static bool dlr_hex_n(const char *s, size_t want)
{
    size_t n = 0;
    return s && zcl_dlr_sha_ok(s, &n) && n == want && s[n] == '\0';
}

/* A manifest string field, copied; false when absent, not a string or long. */
static bool dlr_offer_str(const struct json_value *doc, const char *key,
                          char *dst, size_t cap)
{
    const struct json_value *v = json_get(doc, key);
    return v && v->type == JSON_STR && json_get_str(v) &&
           snprintf(dst, cap, "%s", json_get_str(v)) < (int)cap;
}

static bool dlr_offer_fields(const struct json_value *doc, struct dlr_offer *o)
{
    char schema[48];
    return dlr_offer_str(doc, "schema", schema, sizeof(schema)) &&
           strcmp(schema, DLR_OFFER_SCHEMA) == 0 &&
           dlr_offer_str(doc, "commit", o->commit, sizeof(o->commit)) &&
           dlr_offer_str(doc, "base", o->base, sizeof(o->base)) &&
           dlr_offer_str(doc, "bundle_sha256", o->bsha, sizeof(o->bsha)) &&
           dlr_offer_str(doc, "lane", o->lane, sizeof(o->lane)) &&
           dlr_hex_n(o->commit, 40) && dlr_hex_n(o->base, 40) &&
           dlr_hex_n(o->bsha, 64) && zcl_dlr_lane_ok(o->lane);
}

/* A small JSON object file parsed into doc (always json_free it after). */
static bool dlr_json_read_file(const char *path, struct json_value *doc)
{
    char raw[DLR_OFFER_MAX];
    size_t n = 0;
    bool ok = false;
    FILE *f = fopen(path, "rb");
    if (f) {
        n = fread(raw, 1, sizeof(raw), f);
        ok = !ferror(f) && n > 0 && n < sizeof(raw);
        (void)fclose(f);
    }
    json_init(doc);
    return ok && json_read(doc, raw, n) && doc->type == JSON_OBJ;
}

/* Reads the flat manifest: right schema, 40-hex commit and base, 64-hex
 * bundle sha256, a lane name. */
static bool dlr_offer_read(const char *path, struct dlr_offer *o,
                           struct zcl_command_reply *reply)
{
    struct json_value doc;
    bool ok = dlr_json_read_file(path, &doc) && dlr_offer_fields(&doc, o);
    json_free(&doc);
    if (!ok)
        dlr_offer_fail(o->leaf, reply, "OFFER_BAD_MANIFEST", "manifest",
                       "the offer is not a flat zcl.dev_land_offer.v1 object "
                       "with a 40-hex commit and base, a 64-hex "
                       "bundle_sha256 and a lane",
                       path);
    return ok;
}

/* The bundle's prerequisites from its header ("-<sha> <subject>" lines
 * before the blank line that ends it): how many, and the first. */
static bool dlr_offer_prereq(const char *bundle, char out[48], int *count)
{
    char line[512];
    FILE *f = fopen(bundle, "rb");
    bool ok = f != NULL;
    *count = 0;
    out[0] = '\0';
    while (ok && fgets(line, sizeof(line), f) && line[0] != '\n') {
        if (line[0] != '-')
            continue;
        if (++*count == 1)
            ok = snprintf(out, 48, "%.40s", line + 1) < 48;
    }
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok;
}

/* The bundle against the offer: sha256, git's own verify, one head equal to
 * the commit, one prerequisite equal to the base. */
static bool dlr_offer_bundle(struct dlr_offer *o,
                             struct zcl_command_reply *reply)
{
    char hex[SHA256_OUTPUT_SIZE * 2 + 1];
    int count = 0;
    if (!zcl_dlr_file_sha256(o->r.bundle, hex) || strcmp(hex, o->bsha) != 0)
        dlr_offer_fail(o->leaf, reply, "OFFER_SHA_MISMATCH", "sha256",
                       "the bundle's sha256 is not the one the offer names",
                       o->r.bundle);
    else if (!zcl_dlr_bundle_verify_ok(&o->r))
        dlr_offer_fail(o->leaf, reply, "OFFER_BAD_BUNDLE", "verify",
                       "git bundle verify refused the bundle in this "
                       "checkout",
                       o->r.bundle);
    else if (!zcl_dlr_head_parse(&o->r) || strcmp(o->r.sha, o->commit) != 0)
        dlr_offer_fail(o->leaf, reply, "OFFER_HEAD_MISMATCH", "heads",
                       "the bundle must carry exactly one head, and it must "
                       "be the offered commit",
                       o->commit);
    else if (!dlr_offer_prereq(o->r.bundle, o->prereq, &count) ||
             count != 1 || strcmp(o->prereq, o->base) != 0)
        dlr_offer_fail(o->leaf, reply, "OFFER_BASE_MISMATCH", "base",
                       "the bundle must have exactly one prerequisite, and "
                       "it must be the offered base",
                       o->base);
    else
        return true;
    return false;
}

/* The repository the bundle is verified in: --repo (absolute, inside a
 * checkout) or the checkout above the current directory. */
static bool dlr_offer_root(const struct zcl_command_request *req,
                           struct dlr_offer *o,
                           struct zcl_command_reply *reply)
{
    const char *dir = zcl_dlr_str(req, "repo");
    bool ok = dir ? dir[0] == '/' && zcl_dlr_arg_ok(dir, true) &&
                        zcl_devagent_checkout_root(dir, o->r.root,
                                                   sizeof(o->r.root))
                  : zcl_devagent_checkout_root(NULL, o->r.root,
                                               sizeof(o->r.root));
    if (!ok)
        dlr_offer_fail(o->leaf, reply, "OFFER_BAD_REPO", "repo",
                       "--repo must be the absolute path of a checkout; "
                       "without it the checkout above the current directory "
                       "is used",
                       dir ? dir : "no checkout root above the cwd");
    return ok;
}

#define DLR_CHECK_LEAF "dev.land.check_offer"
#define DLR_ATTEST_LEAF "dev.land.attest_offer"
#define DLR_VERIFY_LEAF "dev.land.verify_offer_receipt"
#define DLR_REVERIFY_LEAF "dev.land.reverify_offer"

static void dlr_offer_ok(const struct dlr_offer *o,
                         struct zcl_command_reply *reply)
{
    (void)json_push_kv_str(&reply->data, "leaf", o->leaf);
    (void)json_push_kv_str(&reply->data, "commit", o->commit);
    (void)json_push_kv_str(&reply->data, "base", o->base);
    (void)json_push_kv_str(&reply->data, "bundle_sha256", o->bsha);
    (void)json_push_kv_str(&reply->data, "verdict", "ok");
}

/* Reads the manifest and runs every check (check_offer and attest_offer
 * share this). NULL, with the refusal in reply, when any of them fails. */
static struct dlr_offer *dlr_offer_checked(const struct zcl_command_request *req,
                                           struct zcl_command_reply *reply,
                                           const char *leaf)
{
    struct dlr_offer *o;
    const char *bundle = zcl_dlr_str(req, "bundle");
    const char *offer = zcl_dlr_str(req, "offer");
    bool ok;
    if (!bundle || !offer) {
        dlr_offer_fail(leaf, reply, "OFFER_BAD_ARGUMENT", "input",
                       "bundle and offer must each name a file",
                       "input.bundle or input.offer missing");
        return NULL;
    }
    o = zcl_calloc(1, sizeof(*o), "dev_land_remote.offer");
    o->leaf = leaf;
    ok = dlr_offer_read(offer, o, reply) && dlr_offer_root(req, o, reply);
    if (ok && !zcl_dlr_bundle_abs(bundle, o->r.bundle, sizeof(o->r.bundle))) {
        dlr_offer_fail(leaf, reply, "OFFER_BAD_BUNDLE", "verify",
                       "bundle is not a usable path", bundle);
        ok = false;
    }
    if (!ok || !dlr_offer_bundle(o, reply)) {
        free(o);
        return NULL;
    }
    return o;
}

/* Read-only: nothing is queued, fetched or written, and no worktree is
 * touched; every check is on bytes already on disk. */
static void dlr_check_offer(const struct zcl_command_request *req,
                            struct zcl_command_reply *reply)
{
    struct dlr_offer *o = dlr_offer_checked(req, reply, DLR_CHECK_LEAF);
    if (o)
        dlr_offer_ok(o, reply);
    free(o);
}

/* ── offer receipts ────────────────────────────────────────────────────── */

#define DLR_RECEIPT_SCHEMA "zcl.dev_land_offer_receipt.v1"
#define DLR_RECEIPT_CHECKS "bundle_sha256,bundle_verify,head,base"
#define DLR_RECEIPT_CHECKS_CX DLR_RECEIPT_CHECKS ",cx_check"
#define DLR_RECEIPT_VERDICT "ok"

/* Hex fields as written; pub and sigb are signer and sig decoded (verify). */
struct dlr_receipt {
    char commit[48], base[48], bsha[80], checks[64], verdict[16];
    char signer[ZCL_DEV_PROOF_SIGNER_PUBKEY_HEX], sig[129];
    uint8_t pub[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES];
    uint8_t sigb[ZCL_DEV_PROOF_SIGNER_SIGNATURE_BYTES];
};

/* The one signed message: the schema as the domain separator, then the five
 * fields in this fixed order, each followed by a newline. */
static size_t dlr_receipt_msg(const struct dlr_receipt *t, char *out,
                              size_t cap)
{
    int n = snprintf(out, cap, DLR_RECEIPT_SCHEMA "\n%s\n%s\n%s\n%s\n%s\n",
                     t->commit, t->base, t->bsha, t->checks, t->verdict);
    return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

/* Signs t's message with this box's key; fills t->signer and t->sig. */
static bool dlr_receipt_sign(struct dlr_receipt *t, const char **why)
{
    char msg[512];
    size_t n = dlr_receipt_msg(t, msg, sizeof(msg));
    uint8_t pub[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES];
    uint8_t sig[ZCL_DEV_PROOF_SIGNER_SIGNATURE_BYTES];
    if (n == 0 || !zcl_dev_proof_signer_sign((const uint8_t *)msg, n, pub, sig,
                                             why))
        return false;
    zcl_hex_encode(pub, sizeof(pub), t->signer);
    zcl_hex_encode(sig, sizeof(sig), t->sig);
    return true;
}

static void dlr_attest_fail(const char *leaf, struct zcl_command_reply *reply,
                            const char *code,
                            const char *msg, const char *evidence)
{
    zcl_dlr_fail(reply, leaf, code, "receipt", msg, evidence);
}

/* The receipt of a bundle that passed every check, signed and written to a
 * path that did not exist. */
static void dlr_attest_write(const struct dlr_offer *o, const char *path,
                             const char *checks,
                             struct zcl_command_reply *reply)
{
    struct dlr_receipt t;
    struct json_value doc;
    const char *why = NULL;
    bool ok;
    memset(&t, 0, sizeof(t));
    (void)snprintf(t.commit, sizeof(t.commit), "%s", o->commit);
    (void)snprintf(t.base, sizeof(t.base), "%s", o->base);
    (void)snprintf(t.bsha, sizeof(t.bsha), "%s", o->bsha);
    (void)snprintf(t.checks, sizeof(t.checks), "%s", checks);
    (void)snprintf(t.verdict, sizeof(t.verdict), "%s", DLR_RECEIPT_VERDICT);
    if (!dlr_receipt_sign(&t, &why)) {
        dlr_attest_fail(o->leaf, reply, "OFFER_RECEIPT_FAILED",
                        "this box's signing key could not sign the receipt",
                        why ? why : "signer_arguments_invalid");
        return;
    }
    json_init(&doc);
    json_set_object(&doc);
    ok = json_push_kv_str(&doc, "schema", DLR_RECEIPT_SCHEMA) &&
         json_push_kv_str(&doc, "commit", t.commit) &&
         json_push_kv_str(&doc, "base", t.base) &&
         json_push_kv_str(&doc, "bundle_sha256", t.bsha) &&
         json_push_kv_str(&doc, "checks", t.checks) &&
         json_push_kv_str(&doc, "verdict", t.verdict) &&
         json_push_kv_str(&doc, "signer", t.signer) &&
         json_push_kv_str(&doc, "signature", t.sig) &&
         zcl_dlr_json_write_new(&doc, path);
    json_free(&doc);
    if (!ok) {
        dlr_attest_fail(o->leaf, reply, "OFFER_RECEIPT_FAILED",
                        "cannot write the receipt", path);
        return;
    }
    dlr_offer_ok(o, reply);
    (void)json_push_kv_str(&reply->data, "receipt", path);
    (void)json_push_kv_str(&reply->data, "signer", t.signer);
}

/* Runs exactly the check_offer checks; only a pass writes a receipt. */
static void dlr_attest_offer(const struct zcl_command_request *req,
                             struct zcl_command_reply *reply)
{
    struct dlr_offer *o;
    const char *out = zcl_dlr_str(req, "receipt_out");
    if (!out || !platform_path_is_absolute(out)) {
        dlr_offer_fail(DLR_ATTEST_LEAF, reply, "OFFER_BAD_ARGUMENT", "input",
                       "receipt_out must be an absolute path",
                       out ? out : "input.receipt_out missing");
        return;
    }
    o = dlr_offer_checked(req, reply, DLR_ATTEST_LEAF);
    if (!o)
        return;
    if (zcl_dlr_exists(out))
        dlr_attest_fail(DLR_ATTEST_LEAF, reply, "OFFER_RECEIPT_EXISTS",
                        "receipt_out already exists; it is never replaced",
                        out);
    else
        dlr_attest_write(o, out, DLR_RECEIPT_CHECKS, reply);
    free(o);
}

static void dlr_verify_fail(struct zcl_command_reply *reply, const char *code,
                            const char *msg, const char *evidence)
{
    zcl_dlr_fail(reply, DLR_VERIFY_LEAF, code, "receipt", msg, evidence);
}

/* The receipt's fields: right schema, 40/64-hex ids, the v1 checks list, an
 * ok verdict, and signer and signature as lowercase hex of the right size. */
static bool dlr_receipt_strs(const struct json_value *doc,
                             struct dlr_receipt *t)
{
    char schema[48];
    return dlr_offer_str(doc, "schema", schema, sizeof(schema)) &&
           strcmp(schema, DLR_RECEIPT_SCHEMA) == 0 &&
           dlr_offer_str(doc, "commit", t->commit, sizeof(t->commit)) &&
           dlr_offer_str(doc, "base", t->base, sizeof(t->base)) &&
           dlr_offer_str(doc, "bundle_sha256", t->bsha, sizeof(t->bsha)) &&
           dlr_offer_str(doc, "checks", t->checks, sizeof(t->checks)) &&
           dlr_offer_str(doc, "verdict", t->verdict, sizeof(t->verdict)) &&
           dlr_offer_str(doc, "signer", t->signer, sizeof(t->signer)) &&
           dlr_offer_str(doc, "signature", t->sig, sizeof(t->sig));
}

static bool dlr_receipt_fields(const struct json_value *doc,
                               struct dlr_receipt *t)
{
    return dlr_receipt_strs(doc, t) && dlr_hex_n(t->commit, 40) &&
           dlr_hex_n(t->base, 40) && dlr_hex_n(t->bsha, 64) &&
           (strcmp(t->checks, DLR_RECEIPT_CHECKS) == 0 ||
            strcmp(t->checks, DLR_RECEIPT_CHECKS_CX) == 0) &&
           strcmp(t->verdict, DLR_RECEIPT_VERDICT) == 0 &&
           zcl_hex_decode_lower(t->signer, t->pub, sizeof(t->pub)) &&
           zcl_hex_decode_lower(t->sig, t->sigb, sizeof(t->sigb));
}

static bool dlr_receipt_read(const char *path, struct dlr_receipt *t,
                             struct zcl_command_reply *reply)
{
    struct json_value doc;
    bool ok;
    memset(t, 0, sizeof(*t));
    ok = dlr_json_read_file(path, &doc) && dlr_receipt_fields(&doc, t);
    json_free(&doc);
    if (!ok)
        dlr_verify_fail(reply, "OFFER_RECEIPT_BAD",
                        "not a zcl.dev_land_offer_receipt.v1 object with the "
                        "v1 checks, verdict ok and hex signer and signature",
                        path);
    return ok;
}

/* The signature through the box's signer: its own key, or one on its
 * signers.allow list. */
static bool dlr_receipt_verify(const struct dlr_receipt *t,
                               struct zcl_command_reply *reply)
{
    char msg[512];
    size_t n = dlr_receipt_msg(t, msg, sizeof(msg));
    const char *why = NULL;
    if (n > 0 && zcl_dev_proof_signer_verify((const uint8_t *)msg, n, t->pub,
                                             t->sigb, &why))
        return true;
    if (why && strcmp(why, ZCL_DEV_PROOF_SIGNER_WHY_SIGNER_UNKNOWN) == 0)
        dlr_verify_fail(reply, "RECEIPT_SIGNER_UNKNOWN",
                        "the signer is not this box's key and not on its "
                        "signers.allow list",
                        t->signer);
    else
        dlr_verify_fail(reply, "RECEIPT_SIGNATURE_INVALID",
                        "the signature does not verify over the receipt "
                        "fields",
                        why ? why : "signature_invalid");
    return false;
}

/* --offer: the receipt must be about this offer's commit, base and sha. */
static bool dlr_receipt_matches(const struct dlr_receipt *t, const char *offer,
                                struct zcl_command_reply *reply)
{
    struct dlr_offer *o = zcl_calloc(1, sizeof(*o), "dev_land_remote.offer");
    bool ok;
    o->leaf = DLR_VERIFY_LEAF;
    ok = dlr_offer_read(offer, o, reply);
    if (ok && (strcmp(o->commit, t->commit) != 0 ||
               strcmp(o->base, t->base) != 0 ||
               strcmp(o->bsha, t->bsha) != 0)) {
        dlr_verify_fail(reply, "RECEIPT_OFFER_MISMATCH",
                        "the receipt names another commit, base or bundle "
                        "sha256 than the offer",
                        offer);
        ok = false;
    }
    free(o);
    return ok;
}

/* Read-only: parses, rebuilds the signed message and verifies it. */
static void dlr_verify_offer_receipt(const struct zcl_command_request *req,
                                     struct zcl_command_reply *reply)
{
    struct dlr_receipt t;
    const char *path = zcl_dlr_str(req, "receipt");
    const char *offer = zcl_dlr_str(req, "offer");
    if (!path) {
        dlr_verify_fail(reply, "OFFER_BAD_ARGUMENT", "receipt must name a file",
                        "input.receipt missing");
        return;
    }
    if (!dlr_receipt_read(path, &t, reply) || !dlr_receipt_verify(&t, reply) ||
        (offer && !dlr_receipt_matches(&t, offer, reply)))
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DLR_VERIFY_LEAF);
    (void)json_push_kv_str(&reply->data, "commit", t.commit);
    (void)json_push_kv_str(&reply->data, "base", t.base);
    (void)json_push_kv_str(&reply->data, "signer", t.signer);
    (void)json_push_kv_str(&reply->data, "verdict", t.verdict);
    (void)json_push_kv_str(&reply->data, "checks", t.checks);
}

/* ── reverify_offer ────────────────────────────────────────────────────── */

#define DLR_CX_MS (30 * 60 * 1000)
#define DLR_BASELINE "tools/lint/cyclomatic_complexity_baseline.txt"
#define DLR_FUNCS_MAX 1024u

/* One re-verification: the scratch worktree, the temporary ref and the unit
 * (the one changed .c and the functions whose baseline rows are deleted). */
struct dlr_rv {
    struct dlr_offer *o;
    char tmpdir[PLATFORM_TEMP_PATH_MAX];
    char wt[PLATFORM_TEMP_PATH_MAX + 8];
    char ref[64];
    char file[256];
    char funcs[DLR_FUNCS_MAX];
};

static bool dlr_rv_fail(struct zcl_command_reply *reply, const char *code,
                        const char *phase, const char *msg,
                        const char *evidence)
{
    zcl_dlr_fail(reply, DLR_REVERIFY_LEAF, code, phase, msg, evidence);
    return false;
}

static int dlr_ogit(const char *dir, const char *const *args, char *out,
                    size_t cap)
{
    return zcl_native_dev_land_git(dir, args, out, cap, DLR_MS);
}

/* The bundle head into refs/z23-reverify/<sha12>, checked to be the commit. */
static bool dlr_rv_fetch(struct dlr_rv *rv, struct zcl_command_reply *reply)
{
    const struct dlr_offer *o = rv->o;
    char spec[512], sink[512];
    const char *fetch[] = {"fetch", "--quiet", o->r.bundle, spec, NULL};
    const char *rp[] = {"rev-parse", "--verify", "--quiet", rv->ref, NULL};
    (void)snprintf(rv->ref, sizeof(rv->ref), "refs/z23-reverify/%.12s",
                   o->commit);
    (void)snprintf(spec, sizeof(spec), "+%s:%s", o->r.ref, rv->ref);
    if (dlr_ogit(o->r.root, fetch, sink, sizeof(sink)) == 0 &&
        dlr_ogit(o->r.root, rp, sink, sizeof(sink)) == 0) {
        sink[strcspn(sink, "\r\n")] = '\0';
        if (strcmp(sink, o->commit) == 0)
            return true;
    }
    return dlr_rv_fail(reply, "REVERIFY_SETUP", "fetch",
                       "could not fetch the bundle head into the temporary "
                       "ref",
                       rv->ref);
}

/* A detached worktree at the offered base under a private temp directory. */
static bool dlr_rv_worktree(struct dlr_rv *rv, struct zcl_command_reply *reply)
{
    const struct dlr_offer *o = rv->o;
    const char *add[] = {"-c",       "core.hooksPath=/dev/null",
                         "worktree", "add",
                         "--quiet",  "--detach",
                         rv->wt,     o->base,
                         NULL};
    char sink[512];
    if (!platform_temp_directory_create("z23-reverify-", rv->tmpdir,
                                        sizeof(rv->tmpdir)) ||
        snprintf(rv->wt, sizeof(rv->wt), "%s/wt", rv->tmpdir) >=
            (int)sizeof(rv->wt) ||
        dlr_ogit(o->r.root, add, sink, sizeof(sink)) != 0)
        return dlr_rv_fail(reply, "REVERIFY_SETUP", "worktree",
                           "could not add a scratch worktree at the offered "
                           "base",
                           o->base);
    return true;
}

/* The offered change as uncommitted edits on its base. */
static bool dlr_rv_apply(struct dlr_rv *rv, struct zcl_command_reply *reply)
{
    const char *cp[] = {"cherry-pick", "--no-commit", rv->o->commit, NULL};
    char sink[1024];
    if (dlr_ogit(rv->wt, cp, sink, sizeof(sink)) == 0)
        return true;
    return dlr_rv_fail(reply, "REVERIFY_APPLY", "apply",
                       "the offered commit does not apply cleanly on its "
                       "base",
                       rv->o->commit);
}

/* One changed path: the baseline is allowed, one .c names the unit, any
 * other path (or a second .c) makes the commit not a split. */
static void dlr_rv_path(struct dlr_rv *rv, const char *p, int *cfiles,
                        bool *other)
{
    size_t n = strlen(p);
    if (n == 0 || strcmp(p, DLR_BASELINE) == 0)
        return;
    if (n > 2 && strcmp(p + n - 2, ".c") == 0 && ++*cfiles == 1 &&
        snprintf(rv->file, sizeof(rv->file), "%s", p) < (int)sizeof(rv->file))
        return;
    *other = true;
}

static bool dlr_rv_not_split(struct zcl_command_reply *reply, const char *what)
{
    return dlr_rv_fail(reply, "REVERIFY_NOT_A_SPLIT", "unit",
                       "the offered commit must change exactly one .c file "
                       "and, optionally, the complexity baseline, and "
                       "delete a baseline row of that file",
                       what);
}

static bool dlr_rv_files(struct dlr_rv *rv, struct zcl_command_reply *reply)
{
    const char *args[] = {"diff", "--cached", "--name-only", "--no-renames",
                          NULL};
    char out[4096];
    int cfiles = 0;
    bool other = false;
    if (dlr_ogit(rv->wt, args, out, sizeof(out)) != 0)
        return dlr_rv_fail(reply, "REVERIFY_SETUP", "unit",
                           "could not list the applied change", rv->wt);
    for (char *p = out; *p;) {
        char *end = p + strcspn(p, "\n");
        bool last = *end == '\0';
        *end = '\0';
        dlr_rv_path(rv, p, &cfiles, &other);
        p = last ? end : end + 1;
    }
    return (cfiles == 1 && !other) ? true
                                   : dlr_rv_not_split(reply, rv->o->commit);
}

/* Appends the function of one "-<file>:<fn>:<M>" row unless the diff also
 * has a "+" row for it (a pin that was lowered, not deleted). */
static bool dlr_rv_row(struct dlr_rv *rv, const char *diff, const char *line,
                       size_t len, size_t *n)
{
    char pre[300], needle[400];
    const char *name, *colon = NULL;
    int w = snprintf(pre, sizeof(pre), "-%s:", rv->file);
    if (w <= 0 || (size_t)w >= sizeof(pre) || len <= (size_t)w ||
        strncmp(line, pre, (size_t)w) != 0)
        return true;
    name = line + w;
    for (const char *c = name; c < line + len; c++)
        if (*c == ':')
            colon = c;
    if (!colon || colon == name)
        return true;
    (void)snprintf(needle, sizeof(needle), "\n+%s:%.*s:", rv->file,
                   (int)(colon - name), name);
    if (strstr(diff, needle))
        return true;
    w = snprintf(rv->funcs + *n, DLR_FUNCS_MAX - *n, "%s%.*s", *n ? "," : "",
                 (int)(colon - name), name);
    if (w < 0 || (size_t)w >= DLR_FUNCS_MAX - *n)
        return false;
    *n += (size_t)w;
    return true;
}

/* The functions whose baseline rows for rv->file the commit deletes. */
static bool dlr_rv_funcs(struct dlr_rv *rv, struct zcl_command_reply *reply)
{
    const char *args[] = {"diff", "--cached", "-U0", "--no-color",
                          "--",   DLR_BASELINE, NULL};
    char out[16384];
    size_t n = 0;
    bool ok = dlr_ogit(rv->wt, args, out, sizeof(out)) == 0;
    rv->funcs[0] = '\0';
    for (const char *p = out; ok && *p;) {
        size_t len = strcspn(p, "\n");
        ok = dlr_rv_row(rv, out, p, len, &n);
        p += len + (p[len] ? 1 : 0);
    }
    if (ok && n > 0)
        return true;
    return dlr_rv_not_split(reply, rv->file);
}

/* dev cx check wants the diff to be the one .c and applies the baseline
 * tighten itself: put the baseline back to the offered base. */
static bool dlr_rv_baseline(struct dlr_rv *rv, struct zcl_command_reply *reply)
{
    const char *args[] = {"checkout", "--quiet", "HEAD", "--", DLR_BASELINE,
                          NULL};
    char sink[512];
    if (dlr_ogit(rv->wt, args, sink, sizeof(sink)) == 0)
        return true;
    return dlr_rv_fail(reply, "REVERIFY_SETUP", "unit",
                       "could not restore the baseline to the offered base",
                       DLR_BASELINE);
}

static bool dlr_copy_file(const char *src, const char *dst)
{
    unsigned char buf[8192];
    size_t n;
    bool ok = true;
    FILE *in = fopen(src, "rb");
    FILE *out = in ? fopen(dst, "wb") : NULL;
    if (!out) {
        if (in)
            (void)fclose(in);
        return false;
    }
    while (ok && (n = fread(buf, 1, sizeof(buf), in)) > 0)
        ok = fwrite(buf, 1, n, out) == n;
    ok = ok && !ferror(in);
    (void)fclose(in);
    return fclose(out) == 0 && ok;
}

/* dev cx check runs the worktree's own build/bin/z23-lint: copy the
 * repository's into the scratch worktree. */
static bool dlr_rv_lint(struct dlr_rv *rv, struct zcl_command_reply *reply)
{
    char src[DLR_PATH + 32], dir[PLATFORM_TEMP_PATH_MAX + 32], dst[sizeof(dir) + 16];
    bool ok = snprintf(src, sizeof(src), "%s/build/bin/z23-lint",
                       rv->o->r.root) < (int)sizeof(src);
    ok = ok && snprintf(dir, sizeof(dir), "%s/build", rv->wt) <
                   (int)sizeof(dir) &&
         platform_private_directory_ensure(dir);
    ok = ok && snprintf(dir, sizeof(dir), "%s/build/bin", rv->wt) <
                   (int)sizeof(dir) &&
         platform_private_directory_ensure(dir);
    ok = ok && snprintf(dst, sizeof(dst), "%s/z23-lint", dir) <
                   (int)sizeof(dst) &&
         dlr_copy_file(src, dst) && chmod(dst, 0755) == 0;
    if (!ok)
        return dlr_rv_fail(reply, "REVERIFY_SETUP", "lint",
                           "could not copy the repository's build/bin/z23-lint "
                           "into the scratch worktree",
                           src);
    return true;
}

/* The program that runs `dev cx check`: this binary; ZCL_TESTING builds may
 * name another with ZCL_LAND_REVERIFY_CX. */
static bool dlr_rv_cx_bin(char *out, size_t cap)
{
#if defined(ZCL_TESTING)
    const char *p = getenv("ZCL_LAND_REVERIFY_CX");
    if (p && p[0])
        return snprintf(out, cap, "%s", p) < (int)cap;
#endif
    return os_proc_exe_path(out, cap);
}

static bool dlr_rv_cx_pass(const struct json_value *doc)
{
    return json_get_bool(json_get(doc, "ok")) &&
           strcmp(json_get_str(json_get(json_get(doc, "data"), "verdict")),
                  "pass") == 0;
}

/* The child's reply as JSON (doc is always json_free'd by the caller). */
static bool dlr_rv_cx_doc(const char *text, struct json_value *doc)
{
    json_init(doc);
    return json_read(doc, text, strlen(text)) && doc->type == JSON_OBJ;
}

static bool dlr_rv_cx(struct dlr_rv *rv, struct zcl_command_reply *reply)
{
    char bin[DLR_PATH], a_wt[sizeof(rv->wt) + 16], a_file[300];
    char a_fn[DLR_FUNCS_MAX + 16], text[16384], ev[700];
    const char *argv[] = {bin,    "dev", "cx", "check", a_wt, a_file, a_fn, NULL};
    struct json_value doc;
    const struct json_value *err;
    bool parsed, pass;
    int rc;
    text[0] = '\0';
    if (!dlr_rv_cx_bin(bin, sizeof(bin)) ||
        snprintf(a_wt, sizeof(a_wt), "--worktree=%s", rv->wt) >=
            (int)sizeof(a_wt) ||
        snprintf(a_file, sizeof(a_file), "--file=%s", rv->file) >=
            (int)sizeof(a_file) ||
        snprintf(a_fn, sizeof(a_fn), "--functions=%s", rv->funcs) >=
            (int)sizeof(a_fn))
        return dlr_rv_fail(reply, "REVERIFY_SETUP", "cx_check",
                           "cannot build the dev cx check command", rv->file);
    rc = zcl_spawn_capture_in_dir_observed(argv, rv->wt, text, sizeof(text),
                                           DLR_CX_MS, NULL);
    parsed = dlr_rv_cx_doc(text, &doc);
    pass = rc == 0 && parsed && dlr_rv_cx_pass(&doc);
    err = parsed ? json_get(&doc, "error") : NULL;
    (void)snprintf(ev, sizeof(ev), "exit=%d code=%.64s detail=%.400s", rc,
                   json_get_str(json_get(err, "code")),
                   parsed ? json_get_str(json_get(err, "evidence"))
                          : "no JSON reply");
    json_free(&doc);
    if (pass)
        return true;
    return dlr_rv_fail(reply, "REVERIFY_CX_FAILED", "cx_check",
                       "dev cx check did not pass on the offered change in a "
                       "scratch worktree",
                       ev);
}

/* A pass: the check_offer reply plus the unit, and a receipt when asked. */
static void dlr_rv_finish(struct dlr_rv *rv, const char *out,
                          struct zcl_command_reply *reply)
{
    if (out)
        dlr_attest_write(rv->o, out, DLR_RECEIPT_CHECKS_CX, reply);
    else
        dlr_offer_ok(rv->o, reply);
    if (reply->status == ZCL_COMMAND_STATUS_PASSED) {
        (void)json_push_kv_str(&reply->data, "file", rv->file);
        (void)json_push_kv_str(&reply->data, "functions", rv->funcs);
    }
}

/* Removes the scratch worktree and the temporary ref, whatever happened. */
static void dlr_rv_cleanup(const struct dlr_rv *rv)
{
    const char *root = rv->o->r.root;
    const char *rm[] = {"worktree", "remove", "--force", rv->wt, NULL};
    const char *prune[] = {"worktree", "prune", NULL};
    const char *del[] = {"update-ref", "-d", rv->ref, NULL};
    char sink[512];
    if (rv->wt[0]) {
        (void)dlr_ogit(root, rm, sink, sizeof(sink));
        (void)dlr_ogit(root, prune, sink, sizeof(sink));
    }
    if (rv->ref[0])
        (void)dlr_ogit(root, del, sink, sizeof(sink));
    if (rv->tmpdir[0])
        (void)platform_private_directory_remove_empty(rv->tmpdir);
}

static void dlr_rv_run(struct dlr_rv *rv, const char *out,
                       struct zcl_command_reply *reply)
{
    if (dlr_rv_fetch(rv, reply) && dlr_rv_worktree(rv, reply) &&
        dlr_rv_apply(rv, reply) && dlr_rv_files(rv, reply) &&
        dlr_rv_funcs(rv, reply) && dlr_rv_baseline(rv, reply) &&
        dlr_rv_lint(rv, reply) &&
        dlr_rv_cx(rv, reply))
        dlr_rv_finish(rv, out, reply);
}

/* check_offer's checks, then the offered change rebuilt on its base in a
 * scratch worktree and `dev cx check` re-run on it; with receipt_out a pass
 * is signed like attest_offer's, plus the cx_check check. */
static void dlr_reverify_offer(const struct zcl_command_request *req,
                               struct zcl_command_reply *reply)
{
    const char *out = zcl_dlr_str(req, "receipt_out");
    struct dlr_offer *o;
    struct dlr_rv *rv;
    if (out && !platform_path_is_absolute(out)) {
        dlr_offer_fail(DLR_REVERIFY_LEAF, reply, "OFFER_BAD_ARGUMENT", "input",
                       "receipt_out must be an absolute path", out);
        return;
    }
    o = dlr_offer_checked(req, reply, DLR_REVERIFY_LEAF);
    if (!o)
        return;
    if (out && zcl_dlr_exists(out)) {
        dlr_attest_fail(DLR_REVERIFY_LEAF, reply, "OFFER_RECEIPT_EXISTS",
                        "receipt_out already exists; it is never replaced",
                        out);
    } else {
        rv = zcl_calloc(1, sizeof(*rv), "dev_land_remote.reverify");
        rv->o = o;
        dlr_rv_run(rv, out, reply);
        dlr_rv_cleanup(rv);
        free(rv);
    }
    free(o);
}

bool zcl_dlr_offer_dispatch(const char *path,
                            const struct zcl_command_request *req,
                            struct zcl_command_reply *reply)
{
    if (!path)
        return false;
    if (strcmp(path, DLR_CHECK_LEAF) == 0)
        dlr_check_offer(req, reply);
    else if (strcmp(path, DLR_ATTEST_LEAF) == 0)
        dlr_attest_offer(req, reply);
    else if (strcmp(path, DLR_VERIFY_LEAF) == 0)
        dlr_verify_offer_receipt(req, reply);
    else if (strcmp(path, DLR_REVERIFY_LEAF) == 0)
        dlr_reverify_offer(req, reply);
    else
        return false;
    return true;
}
