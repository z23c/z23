/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the few helpers native_dev_land_remote.c (send, receive) shares
 *          with native_dev_land_offer.c (check_offer, attest_offer,
 *          verify_offer_receipt, reverify_offer).
 */
#ifndef ZCL_NATIVE_DEV_LAND_REMOTE_SHARED_H
#define ZCL_NATIVE_DEV_LAND_REMOTE_SHARED_H

#include <stdbool.h>
#include <stddef.h>

#include "command/native_command.h"
#include "crypto/sha256.h"
#include "json/json.h"

#define DLR_PATH 4096u

/* One bundle being checked or received: the checkout, the bundle, its head. */
struct dlr_recv {
    char root[DLR_PATH];
    char bundle[DLR_PATH];
    char wt[DLR_PATH + 64];
    char sha[80];
    char ref[256];
    char branch[96];
};

/* A non-empty string input, or NULL. */
const char *zcl_dlr_str(const struct zcl_command_request *req, const char *key);
/* A leaf refusal: data.leaf plus the failed reply. */
void zcl_dlr_fail(struct zcl_command_reply *reply, const char *leaf,
                  const char *code, const char *phase, const char *msg,
                  const char *evidence);
bool zcl_dlr_lane_ok(const char *s);
bool zcl_dlr_arg_ok(const char *s, bool bare);
/* 40 or 64 lowercase hex characters from s; *len is the run length. */
bool zcl_dlr_sha_ok(const char *s, size_t *len);
bool zcl_dlr_exists(const char *path);
bool zcl_dlr_bundle_abs(const char *in, char *out, size_t cap);
/* git bundle verify of r->bundle in r->root. */
bool zcl_dlr_bundle_verify_ok(const struct dlr_recv *r);
/* Exactly one head "<sha> <ref>" into r->sha and r->ref. */
bool zcl_dlr_head_parse(struct dlr_recv *r);
bool zcl_dlr_file_sha256(const char *path,
                         char hex[SHA256_OUTPUT_SIZE * 2 + 1]);
/* One JSON object plus a newline, created exclusively at path. */
bool zcl_dlr_json_write_new(const struct json_value *doc, const char *path);

#define DLR_QUAL_RECEIPTS_MAX 32

/* What qualify_offer counted; q->code is the refusal code when it refused. */
struct dlr_qual {
    char commit[48], base[48], code[64];
    char signers[DLR_QUAL_RECEIPTS_MAX][65];
    int required, qualified, duplicates;
};

/* qualify_offer's count: true when at least `require` distinct signers other
 * than this box's own key re-verified the offer. A refusal is in reply and
 * q->code, with the counts in q. */
bool zcl_dlr_qualify(const char *offer, const char *receipts, int require,
                     struct dlr_qual *q, struct zcl_command_reply *reply);

/* check_offer, attest_offer, verify_offer_receipt, reverify_offer,
 * qualify_offer: true when path named one of them. */
bool zcl_dlr_offer_dispatch(const char *path,
                            const struct zcl_command_request *req,
                            struct zcl_command_reply *reply);

#endif
