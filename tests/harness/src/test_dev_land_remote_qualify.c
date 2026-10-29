/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance tests for dev.land.qualify_offer
 * (tools/command/native_dev_land_offer.c). "Lab B" and "lab C" are foreign
 * signer keys made
 * the way the receipt tests make one: another XDG_STATE_HOME. Their receipts
 * are signed here over the receipt message with checks that include cx_check
 * (what reverify_offer writes), and their keys are put on this box's
 * signers.allow. Every case asserts the exact reply code. */

#include "test/test_core.h"
#include "test/test_dev_land_remote_rig.h"

#include "base/hex.h"
#include "dev_proof_signer.h"
#include "zsha256/zsha256.h"

#define DLQ_CX "bundle_sha256,bundle_verify,head,base,cx_check"
#define DLQ_PLAIN "bundle_sha256,bundle_verify,head,base"

struct dlq_fixture {
    struct dlt_rig r;
    char tip[64], bsha[ZSHA256_HEX_LEN];
    char bundle[900], offer[900];
};

/* Signs a receipt for the fixture's offer with the key under `state` (the
 * box's own, or a foreign lab's) and writes it to path. signer gets its key. */
static bool dlq_sign(const struct dlq_fixture *f, const char *state,
                     const char *path, const char *checks, char signer[65])
{
    char msg[512], body[1024], sighex[129];
    uint8_t pub[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES];
    uint8_t sig[ZCL_DEV_PROOF_SIGNER_SIGNATURE_BYTES];
    const char *why = NULL;
    int n = snprintf(msg, sizeof(msg),
                     "zcl.dev_land_offer_receipt.v1\n%s\n%s\n%s\n%s\nok\n",
                     f->tip, f->r.base_sha, f->bsha, checks);
    bool ok;
    (void)mkdir(state, 0700);
    (void)setenv("XDG_STATE_HOME", state, 1);
    ok = n > 0 && zcl_dev_proof_signer_sign((const uint8_t *)msg, (size_t)n,
                                            pub, sig, &why);
    (void)setenv("XDG_STATE_HOME", f->r.state, 1);
    if (!ok)
        return false;
    zcl_hex_encode(pub, sizeof(pub), signer);
    zcl_hex_encode(sig, sizeof(sig), sighex);
    (void)snprintf(body, sizeof(body),
                   "{\"schema\":\"zcl.dev_land_offer_receipt.v1\","
                   "\"commit\":\"%s\",\"base\":\"%s\",\"bundle_sha256\":\"%s\","
                   "\"checks\":\"%s\",\"verdict\":\"ok\",\"signer\":\"%s\","
                   "\"signature\":\"%s\"}\n",
                   f->tip, f->r.base_sha, f->bsha, checks, signer, sighex);
    return dlt_write(path, body, 0644);
}

/* Adds a foreign lab's key to this box's signers.allow. */
static bool dlq_allow(const char *signer)
{
    char allow[1024], line[80];
    if (!zcl_dev_proof_signer_paths(NULL, 0, allow, sizeof(allow)))
        return false;
    (void)snprintf(line, sizeof(line), "%s\n", signer);
    FILE *fp = fopen(allow, "a");
    bool ok = fp && fputs(line, fp) >= 0;
    if (fp)
        ok = fclose(fp) == 0 && ok;
    return ok && chmod(allow, 0600) == 0;
}

static bool dlq_fixture(struct dlq_fixture *f, const char *tag)
{
    struct dlt_call c;
    if (!dlt_rig(&f->r, tag) || !dlt_commit(f->r.sender, "a.txt", "a\n") ||
        DLT_GIT(f->tip, sizeof(f->tip), f->r.sender, "rev-parse", "HEAD") != 0)
        return false;
    f->tip[strcspn(f->tip, "\n")] = '\0';
    (void)snprintf(f->bundle, sizeof(f->bundle), "%s/q.bundle", f->r.base);
    (void)snprintf(f->offer, sizeof(f->offer), "%s/q.bundle.offer.json",
                   f->r.base);
    dlt_send_x(&c, &f->r, f->tip, f->bundle, false);
    (void)snprintf(f->bsha, sizeof(f->bsha), "%s",
                   json_get_str(json_get(&c.reply.data, "bundle_sha256")));
    bool ok = c.reply.status == ZCL_COMMAND_STATUS_PASSED;
    dlt_end(&c);
    return ok;
}

static void dlq_qualify(struct dlt_call *c, const struct dlq_fixture *f,
                        const char *receipts, int require)
{
    dlt_begin(c, "dev.land.qualify_offer");
    (void)json_push_kv_str(&c->input, "offer", f->offer);
    (void)json_push_kv_str(&c->input, "receipts", receipts);
    if (require)
        (void)json_push_kv_int(&c->input, "require", require);
    zcl_native_handle_dev_land_remote(&c->request, &c->reply);
}

static bool dlq_ready(const struct dlt_call *c, int qualified, int duplicates,
                      int required)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED &&
           strcmp(json_get_str(json_get(&c->reply.data, "verdict")), "ready") ==
               0 &&
           json_get_int(json_get(&c->reply.data, "qualified")) == qualified &&
           json_get_int(json_get(&c->reply.data, "duplicates")) == duplicates &&
           json_get_int(json_get(&c->reply.data, "required")) == required;
}

static int dlq_qualify_cases(void)
{
    int failures = 0;
    struct dlq_fixture f;
    struct dlt_call c;
    char sb[900], sc[900], sa[900], rb[900], rc[900], ra[900], rn[900];
    char bad[900], both[2000], twice[2000], bsign[65], csign[65], asign[65];
    char nsign[65];
    if (!dlq_fixture(&f, "qualify")) {
        printf("rig setup FAILED\n");
        return 1;
    }
    (void)snprintf(sb, sizeof(sb), "%s/lab-b", f.r.base);
    (void)snprintf(sc, sizeof(sc), "%s/lab-c", f.r.base);
    (void)snprintf(sa, sizeof(sa), "%s", f.r.state);
    (void)snprintf(rb, sizeof(rb), "%s/b.receipt.json", f.r.base);
    (void)snprintf(rc, sizeof(rc), "%s/c.receipt.json", f.r.base);
    (void)snprintf(ra, sizeof(ra), "%s/a.receipt.json", f.r.base);
    (void)snprintf(rn, sizeof(rn), "%s/n.receipt.json", f.r.base);
    (void)snprintf(bad, sizeof(bad), "%s/bad.receipt.json", f.r.base);
    (void)snprintf(both, sizeof(both), "%s,%s", rb, rc);
    (void)snprintf(twice, sizeof(twice), "%s,%s", rb, rb);
    if (!dlq_sign(&f, sb, rb, DLQ_CX, bsign) ||
        !dlq_sign(&f, sc, rc, DLQ_CX, csign) ||
        !dlq_sign(&f, sa, ra, DLQ_CX, asign) ||
        !dlq_sign(&f, sb, rn, DLQ_PLAIN, nsign) || !dlq_allow(bsign) ||
        !dlq_allow(csign) || !dlt_tweak(rb, bad, "signature")) {
        printf("receipt setup FAILED\n");
        dlt_done(&f.r);
        return 1;
    }

    TEST("land.qualify_offer: lab B's re-verified receipt on the allow list "
         "is ready with one signer") {
        dlq_qualify(&c, &f, rb, 0);
        ASSERT(dlq_ready(&c, 1, 0, 1));
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "commit")), f.tip);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "base")),
                      f.r.base_sha);
        ASSERT_EQ((int)json_size(json_get(&c.reply.data, "signers")), 1);
        ASSERT_STR_EQ(json_get_str(json_at(json_get(&c.reply.data, "signers"),
                                           0)),
                      bsign);
        dlt_end(&c);
        PASS();
    }

    TEST("land.qualify_offer: the same receipt twice counts once and reports "
         "one duplicate") {
        dlq_qualify(&c, &f, twice, 0);
        ASSERT(dlq_ready(&c, 1, 1, 1));
        dlt_end(&c);
        PASS();
    }

    TEST("land.qualify_offer: two labs meet require=2") {
        dlq_qualify(&c, &f, both, 2);
        ASSERT(dlq_ready(&c, 2, 0, 2));
        dlt_end(&c);
        PASS();
    }

    TEST("land.qualify_offer: this box's own receipt refuses "
         "QUALIFY_SIGNER_NOT_DISTINCT") {
        dlq_qualify(&c, &f, ra, 0);
        ASSERT(dlt_refused(&c, "QUALIFY_SIGNER_NOT_DISTINCT"));
        ASSERT_STR_EQ(c.reply.error.evidence, ra);
        dlt_end(&c);
        PASS();
    }

    TEST("land.qualify_offer: a 4-check receipt refuses "
         "QUALIFY_NOT_REVERIFIED") {
        dlq_qualify(&c, &f, rn, 0);
        ASSERT(dlt_refused(&c, "QUALIFY_NOT_REVERIFIED"));
        ASSERT_STR_EQ(c.reply.error.evidence, rn);
        dlt_end(&c);
        PASS();
    }

    TEST("land.qualify_offer: one flipped signature byte refuses "
         "RECEIPT_SIGNATURE_INVALID with the receipt's path") {
        dlq_qualify(&c, &f, bad, 0);
        ASSERT(dlt_refused(&c, "RECEIPT_SIGNATURE_INVALID"));
        ASSERT_STR_EQ(c.reply.error.evidence, bad);
        dlt_end(&c);
        PASS();
    }

    TEST("land.qualify_offer: require=2 with one signer refuses "
         "QUALIFY_SHORT") {
        dlq_qualify(&c, &f, twice, 2);
        ASSERT(dlt_refused(&c, "QUALIFY_SHORT"));
        ASSERT(strstr(c.reply.error.evidence, "qualified=1 required=2 "
                                              "duplicates=1") != NULL);
        dlt_end(&c);
        PASS();
    }

    TEST("land.qualify_offer: require outside 1..16 refuses "
         "QUALIFY_BAD_ARGUMENT") {
        dlq_qualify(&c, &f, rb, 17);
        ASSERT(dlt_refused(&c, "QUALIFY_BAD_ARGUMENT"));
        dlt_end(&c);
        dlq_qualify(&c, &f, rb, -1);
        ASSERT(dlt_refused(&c, "QUALIFY_BAD_ARGUMENT"));
        dlt_end(&c);
        PASS();
    }

_test_next:;
    dlt_done(&f.r);
    return failures;
}

int dlq_remote_cases(void);
int dlq_remote_cases(void)
{
    return dlq_qualify_cases();
}
