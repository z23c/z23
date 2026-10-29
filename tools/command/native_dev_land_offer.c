/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land.check_offer / attest_offer / verify_offer_receipt: the offer
 * manifest and the signed receipt, moved out of native_dev_land_remote.c
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
 */

#include "command/native_command.h"
#include "command/native_dev_land_precheck.h"
#include "command/native_dev_land_remote_shared.h"
#include "command/native_devagent.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/path_compat.h"
#include "crypto/sha256.h"
#include "dev_proof_signer.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void dlr_attest_fail(struct zcl_command_reply *reply, const char *code,
                            const char *msg, const char *evidence)
{
    zcl_dlr_fail(reply, DLR_ATTEST_LEAF, code, "receipt", msg, evidence);
}

/* The receipt of a bundle that passed every check, signed and written to a
 * path that did not exist. */
static void dlr_attest_write(const struct dlr_offer *o, const char *path,
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
    (void)snprintf(t.checks, sizeof(t.checks), "%s", DLR_RECEIPT_CHECKS);
    (void)snprintf(t.verdict, sizeof(t.verdict), "%s", DLR_RECEIPT_VERDICT);
    if (!dlr_receipt_sign(&t, &why)) {
        dlr_attest_fail(reply, "OFFER_RECEIPT_FAILED",
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
        dlr_attest_fail(reply, "OFFER_RECEIPT_FAILED",
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
        dlr_attest_fail(reply, "OFFER_RECEIPT_EXISTS",
                        "receipt_out already exists; it is never replaced",
                        out);
    else
        dlr_attest_write(o, out, reply);
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
           strcmp(t->checks, DLR_RECEIPT_CHECKS) == 0 &&
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
    else
        return false;
    return true;
}
