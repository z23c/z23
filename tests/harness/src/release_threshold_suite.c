/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: k-of-n release signing (docs/work/PQ_HYBRID_RELEASE_SIGNATURE.md
 *          6.2). A pin file with `threshold K` accepts a release only when K
 *          DISTINCT pinned pairs each hold a valid hybrid doc over the same
 *          (name, version, root). Every refusal has its own typed code and a
 *          row here: duplicate signer, signers disagreeing on name / version
 *          / root, K above the pinned pairs (a pair pinned twice counts
 *          once), K below 1, one doc when K >= 2, too few matching pairs,
 *          cosigner docs without a threshold, and a v1 doc in a set. The
 *          gate is release_pin_multi_gate, the one both `ops slot install`
 *          and `zcode release verify` call. Fixture seeds only.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/release_pin.h"

#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "zid/zid.h"
#include "zid/zid_hybrid.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define RT_SIGNERS 14
#define RT_SHARED_ED 12 /* signer 0's Ed25519 key, signer 1's SLH-DSA key */
#define RT_SHARED_PQ 13 /* a fresh Ed25519 key, signer 0's SLH-DSA key */

struct rt_signer {
    uint8_t ed_seed[32];
    uint8_t pq_seed[ZRS1_PQ_SEED_SIZE];
    char pair_line[200];
};

struct rt_fx {
    char dir[PATH_MAX];
    struct rt_signer s[RT_SIGNERS];
    uint8_t root[32];
};

static int rt_check(bool ok, const char *what)
{
    printf("release_threshold: %s... %s\n", what, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool rt_write(const char *path, const char *text)
{
    FILE *fp = fopen(path, "wb");
    bool ok = fp && fputs(text, fp) >= 0;
    if (fp)
        ok = fclose(fp) == 0 && ok;
    return ok;
}

static bool rt_signer_init(struct rt_signer *s, uint8_t ed_fill,
                           uint8_t pq_fill)
{
    uint8_t pq_pk[ZRS1_PQ_PK_SIZE], ed_pk[32];
    char ed_hex[65], pq_hex[ZRS1_PQ_PK_SIZE * 2 + 1];
    struct zid_doc doc;
    struct zid_release rel;
    memset(s->ed_seed, ed_fill, sizeof(s->ed_seed));
    for (size_t i = 0; i < ZRS1_PQ_SEED_SIZE; i++)
        s->pq_seed[i] = (uint8_t)(pq_fill + i);
    memset(&rel, 0, sizeof(rel));
    snprintf(rel.name, sizeof(rel.name), "k");
    snprintf(rel.version, sizeof(rel.version), "0");
    if (!zid_release_sign(&doc, &rel, 1, 4102444800ULL, s->ed_seed) ||
        !zid_hybrid_pq_pubkey(pq_pk, s->pq_seed))
        return false;
    memcpy(ed_pk, doc.master_pubkey, 32);
    HexStr(ed_pk, 32, false, ed_hex, sizeof(ed_hex));
    HexStr(pq_pk, sizeof(pq_pk), false, pq_hex, sizeof(pq_hex));
    snprintf(s->pair_line, sizeof(s->pair_line), "zrs1 %s 0 %s", ed_hex,
             pq_hex);
    return true;
}

static bool rt_init(struct rt_fx *fx)
{
    char cwd[PATH_MAX], rm[PATH_MAX + 16];
    memset(fx, 0, sizeof(*fx));
    if (!getcwd(cwd, sizeof(cwd)))
        return false;
    snprintf(fx->dir, sizeof(fx->dir), "%s/test-tmp/%d_rth", cwd,
             (int)getpid());
    snprintf(rm, sizeof(rm), "rm -rf '%s'", fx->dir);
    TEST_DISCARD(system(rm));
    mkdir("./test-tmp", 0755);
    memset(fx->root, 0xAB, sizeof(fx->root));
    bool ok = mkdir(fx->dir, 0755) == 0;
    for (int i = 0; ok && i < RT_SIGNERS; i++) {
        uint8_t ed = (uint8_t)(i < 4 ? 0x41 + i * 0x10 : 0x90 + i);
        uint8_t pq = (uint8_t)(i < 4 ? 0xA0 + i * 0x20 : 0x10 + i * 3);
        if (i == RT_SHARED_ED) {
            ed = 0x41;
            pq = 0xC0;
        } else if (i == RT_SHARED_PQ) {
            ed = 0xEE;
            pq = 0xA0;
        }
        ok = rt_signer_init(&fx->s[i], ed, pq);
    }
    return ok;
}

/* Write signer i's v2 doc over (name, version, root) to <dir>/<file>. */
static bool rt_doc(const struct rt_fx *fx, int i, const char *name,
                   const char *version, const uint8_t root[32],
                   const char *file)
{
    static struct zid_doc_v2 doc;
    static uint8_t wire[ZID_DOC_V2_MAX];
    static char hex[ZID_DOC_V2_MAX * 2 + 1];
    struct zid_release rel;
    char path[PATH_MAX];
    memset(&rel, 0, sizeof(rel));
    snprintf(rel.name, sizeof(rel.name), "%s", name);
    snprintf(rel.version, sizeof(rel.version), "%s", version);
    memcpy(rel.manifest_root, root, 32);
    if (!zid_hybrid_release_sign(&doc, &rel, 1,
                                 (uint64_t)platform_time_wall_unix() + 86400u,
                                 fx->s[i].ed_seed, fx->s[i].pq_seed))
        return false;
    size_t n = zid_hybrid_encode(wire, sizeof(wire), &doc);
    if (n == 0)
        return false;
    HexStr(wire, n, false, hex, sizeof(hex));
    snprintf(path, sizeof(path), "%s/%s", fx->dir, file);
    return rt_write(path, hex);
}

/* A v1 (Ed25519-only) doc by signer i, for the mixed-version row. */
static bool rt_doc_v1(const struct rt_fx *fx, int i, const char *file)
{
    struct zid_doc doc;
    struct zid_release rel;
    uint8_t wire[ZID_DOC_MAX];
    char hex[ZID_DOC_MAX * 2 + 1], path[PATH_MAX];
    memset(&rel, 0, sizeof(rel));
    snprintf(rel.name, sizeof(rel.name), "z23");
    snprintf(rel.version, sizeof(rel.version), "1.0");
    memcpy(rel.manifest_root, fx->root, 32);
    if (!zid_release_sign(&doc, &rel, 1,
                          (uint64_t)platform_time_wall_unix() + 86400u,
                          fx->s[i].ed_seed))
        return false;
    size_t n = zid_doc_encode(wire, sizeof(wire), &doc);
    HexStr(wire, n, false, hex, sizeof(hex));
    snprintf(path, sizeof(path), "%s/%s", fx->dir, file);
    return n > 0 && rt_write(path, hex);
}

/* Pin file <dir>/<file> with the pair lines of the listed signers (a -1
 * ends the list) followed by `extra`. */
static bool rt_pins(const struct rt_fx *fx, const char *file, const int *who,
                    const char *extra)
{
    char text[2048] = "# fixture owners\n", path[PATH_MAX];
    for (; *who >= 0; who++) {
        strcat(text, fx->s[*who].pair_line);
        strcat(text, "\n");
    }
    strcat(text, extra);
    snprintf(path, sizeof(path), "%s/%s", fx->dir, file);
    return rt_write(path, text);
}

/* Run the shared gate: primary doc `primary`, pin file `pins`, cosigners
 * `cos` (comma-separated file names or NULL). Returns the refusal code in
 * *code ("" on accept) and the counts in *th. */
static bool rt_gate(const struct rt_fx *fx, const char *primary,
                    const char *pins, const char *cos, char code[64],
                    struct release_pin_threshold *th)
{
    struct json_value in;
    struct zcl_command_reply reply;
    struct release_pin_doc d;
    struct zid_release rel;
    char path[PATH_MAX], pinp[PATH_MAX], cosp[PATH_MAX * 3] = "";
    const char *rc = NULL;
    snprintf(path, sizeof(path), "%s/%s", fx->dir, primary);
    snprintf(pinp, sizeof(pinp), "%s/%s", fx->dir, pins);
    for (const char *p = cos; p && *p;) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        if (cosp[0])
            strcat(cosp, ",");
        snprintf(cosp + strlen(cosp), sizeof(cosp) - strlen(cosp), "%s/%.*s",
                 fx->dir, (int)len, p);
        p = comma ? comma + 1 : p + len;
    }
    memset(&rel, 0, sizeof(rel));
    memset(th, 0, sizeof(*th));
    if (!release_pin_read_any(path, &d, &rc))
        return false;
    json_init(&in);
    json_set_object(&in);
    json_push_kv_str(&in, "pin_file", pinp);
    if (cos)
        json_push_kv_str(&in, "cosigs", cosp);
    zcl_command_reply_init(&reply, "zcl.release_threshold_test.v1");
    bool ok = release_pin_multi_gate(&in, true, &d,
                                     (uint64_t)platform_time_wall_unix(), &rel,
                                     th, &reply, "test.release.threshold");
    snprintf(code, 64, "%s", ok ? "" : reply.error.code);
    zcl_command_reply_free(&reply);
    json_free(&in);
    return true;
}

static int rt_expect(const struct rt_fx *fx, const char *what,
                     const char *primary, const char *pins, const char *cos,
                     const char *want)
{
    char code[64];
    bool ran = rt_gate(fx, primary, pins, cos, code, &(struct release_pin_threshold){0});
    return rt_check(ran && strcmp(code, want) == 0, what);
}

static int rt_accept(struct rt_fx *fx)
{
    char code[64];
    struct release_pin_threshold th;
    int failures = 0;
    const int ab[] = { 0, 1, -1 };
    const int abc[] = { 0, 1, 2, -1 };
    failures += rt_check(
        rt_doc(fx, 0, "z23", "1.0", fx->root, "a.zid") &&
            rt_doc(fx, 1, "z23", "1.0", fx->root, "b.zid") &&
            rt_doc(fx, 2, "z23", "1.0", fx->root, "c.zid") &&
            rt_pins(fx, "p_ab_k2", ab, "threshold 2\n") &&
            rt_pins(fx, "p_abc_k2", abc, "threshold 2\n") &&
            rt_pins(fx, "p_ab_plain", ab, ""),
        "threshold fixtures");
    failures += rt_check(rt_gate(fx, "a.zid", "p_ab_k2", "b.zid", code, &th) &&
                             code[0] == '\0' && th.threshold == 2 &&
                             th.matched == 2,
                         "K=2 accepts two distinct pinned pairs "
                         "(threshold 2, matched 2)");
    failures += rt_check(rt_gate(fx, "c.zid", "p_abc_k2", "a.zid", code, &th) &&
                             code[0] == '\0' && th.matched == 2,
                         "K=2 of 3 pinned accepts any two of them");
    failures += rt_check(
        rt_gate(fx, "a.zid", "p_abc_k2", "b.zid,c.zid", code, &th) &&
            code[0] == '\0' && th.matched == 3,
        "a third valid signer is counted, not refused");
    failures += rt_check(rt_gate(fx, "a.zid", "p_ab_plain", NULL, code, &th) &&
                             code[0] == '\0' && th.threshold == 0,
                         "no threshold line: one pinned pair still accepts "
                         "and reports no threshold");
    failures += rt_expect(fx, "no threshold line: a single doc from an "
                          "unpinned pair is unchanged RELEASE_UNPINNED",
                          "c.zid", "p_ab_plain", NULL, "RELEASE_UNPINNED");
    return failures;
}

static int rt_refusals(struct rt_fx *fx)
{
    int failures = 0;
    const int ab[] = { 0, 1, -1 };
    const int ac[] = { 0, 2, -1 };
    const int aa[] = { 0, 0, -1 };
    const int aab[] = { 0, 0, 1, -1 };
    failures += rt_expect(fx, "K=2 with one doc is THRESHOLD_SINGLE_DOC",
                          "a.zid", "p_ab_k2", NULL, "THRESHOLD_SINGLE_DOC");
    failures += rt_expect(fx, "the same doc twice is THRESHOLD_DUPLICATE_SIGNER",
                          "a.zid", "p_ab_k2", "a.zid",
                          "THRESHOLD_DUPLICATE_SIGNER");
    failures += rt_check(
        rt_doc(fx, 0, "z23", "1.0", fx->root, "a_again.zid"),
        "second doc by the same pair");
    failures += rt_expect(fx, "a second doc by the same pair is "
                          "THRESHOLD_DUPLICATE_SIGNER", "a.zid", "p_ab_k2",
                          "a_again.zid", "THRESHOLD_DUPLICATE_SIGNER");
    failures += rt_check(rt_pins(fx, "p_ac_k2", ac, "threshold 2\n"),
                         "pins for a and c");
    failures += rt_expect(fx, "a signer whose pair is not pinned counts "
                          "zero: THRESHOLD_NOT_MET", "a.zid", "p_ac_k2",
                          "b.zid", "THRESHOLD_NOT_MET");

    uint8_t other_root[32];
    memset(other_root, 0xCD, sizeof(other_root));
    failures += rt_check(
        rt_doc(fx, 1, "z23", "1.1", fx->root, "b_ver.zid") &&
            rt_doc(fx, 1, "z24", "1.0", fx->root, "b_name.zid") &&
            rt_doc(fx, 1, "z23", "1.0", other_root, "b_root.zid"),
        "disagreeing docs");
    failures += rt_expect(fx, "signers disagreeing on version are "
                          "THRESHOLD_DISAGREE", "a.zid", "p_ab_k2",
                          "b_ver.zid", "THRESHOLD_DISAGREE");
    failures += rt_expect(fx, "signers disagreeing on name are "
                          "THRESHOLD_DISAGREE", "a.zid", "p_ab_k2",
                          "b_name.zid", "THRESHOLD_DISAGREE");
    failures += rt_expect(fx, "signers disagreeing on root are "
                          "THRESHOLD_DISAGREE", "a.zid", "p_ab_k2",
                          "b_root.zid", "THRESHOLD_DISAGREE");

    failures += rt_check(rt_pins(fx, "p_k3", ab, "threshold 3\n") &&
                             rt_pins(fx, "p_aa_k2", aa, "threshold 2\n") &&
                             rt_pins(fx, "p_aab_k3", aab, "threshold 3\n") &&
                             rt_pins(fx, "p_k0", ab, "threshold 0\n") &&
                             rt_pins(fx, "p_kx", ab, "threshold two\n") &&
                             rt_pins(fx, "p_k2k2", ab,
                                     "threshold 2\nthreshold 2\n"),
                         "bad threshold pin files");
    failures += rt_expect(fx, "K above the pinned pairs is "
                          "THRESHOLD_EXCEEDS_PINS", "a.zid", "p_k3",
                          "b.zid", "THRESHOLD_EXCEEDS_PINS");
    failures += rt_expect(fx, "the same pair pinned twice counts once: "
                          "K=2 over one pair is THRESHOLD_EXCEEDS_PINS",
                          "a.zid", "p_aa_k2", "b.zid",
                          "THRESHOLD_EXCEEDS_PINS");
    failures += rt_expect(fx, "pair pinned twice plus one other still "
                          "counts two pairs: K=3 is THRESHOLD_EXCEEDS_PINS",
                          "a.zid", "p_aab_k3", "b.zid",
                          "THRESHOLD_EXCEEDS_PINS");
    failures += rt_expect(fx, "K=0 is THRESHOLD_BELOW_ONE", "a.zid", "p_k0",
                          "b.zid", "THRESHOLD_BELOW_ONE");
    failures += rt_expect(fx, "a non-numeric K is PIN_FILE_INVALID", "a.zid",
                          "p_kx", "b.zid", "PIN_FILE_INVALID");
    failures += rt_expect(fx, "two threshold lines are PIN_FILE_INVALID",
                          "a.zid", "p_k2k2", "b.zid", "PIN_FILE_INVALID");
    failures += rt_expect(fx, "cosigner docs without a threshold line are "
                          "THRESHOLD_MISSING", "a.zid", "p_ab_plain",
                          "b.zid", "THRESHOLD_MISSING");
    failures += rt_expect(fx, "an unreadable cosigner doc is a typed refusal",
                          "a.zid", "p_ab_k2", "nope.zid", "DOC_UNREADABLE");
    failures += rt_check(rt_doc_v1(fx, 1, "b_v1.zid"), "v1 cosigner doc");
    failures += rt_expect(fx, "a v1 doc in a threshold set is "
                          "RELEASE_PQ_REQUIRED", "a.zid", "p_ab_k2",
                          "b_v1.zid", "RELEASE_PQ_REQUIRED");
    return failures;
}

/* Flip the last byte of signer i's v2 doc (inside the SLH-DSA signature, so
 * the Ed25519 half still verifies) and write it to <dir>/<file>. */
static bool rt_doc_bad_pq(const struct rt_fx *fx, int i, const char *file)
{
    char path[PATH_MAX];
    if (!rt_doc(fx, i, "z23", "1.0", fx->root, file))
        return false;
    snprintf(path, sizeof(path), "%s/%s", fx->dir, file);
    FILE *fp = fopen(path, "rb+");
    if (!fp)
        return false;
    char hex[ZID_DOC_V2_MAX * 2 + 2];
    size_t n = fread(hex, 1, sizeof(hex) - 1, fp);
    bool ok = n >= 2;
    if (ok) {
        hex[n - 1] = hex[n - 1] == '0' ? '1' : '0';
        ok = fseek(fp, 0, SEEK_SET) == 0 && fwrite(hex, 1, n, fp) == n;
    }
    return fclose(fp) == 0 && ok;
}

/* Negative rows added after review: a bad SLH-DSA half, a signer that shares
 * only one key with another, huge K, and a set past the 8-doc cap. */
static int rt_more_negative(struct rt_fx *fx)
{
    int failures = 0;
    char files[8][32], seven[512] = "", all[600];
    failures += rt_check(
        rt_doc_bad_pq(fx, 1, "b_badpq.zid") &&
            rt_doc(fx, RT_SHARED_ED, "z23", "1.0", fx->root, "s_ed.zid") &&
            rt_doc(fx, RT_SHARED_PQ, "z23", "1.0", fx->root, "s_pq.zid"),
        "bad-PQ and shared-key docs");
    failures += rt_expect(fx, "Ed25519 valid but SLH-DSA bad refuses the set "
                          "(BAD_PQ_SIGNATURE)", "a.zid", "p_ab_k2",
                          "b_badpq.zid", "BAD_PQ_SIGNATURE");
    failures += rt_expect(fx, "a shared Ed25519 key with a different SLH-DSA "
                          "key is one signer: THRESHOLD_DUPLICATE_SIGNER",
                          "a.zid", "p_ab_k2", "s_ed.zid",
                          "THRESHOLD_DUPLICATE_SIGNER");
    failures += rt_expect(fx, "a shared SLH-DSA key with a different Ed25519 "
                          "key is one signer: THRESHOLD_DUPLICATE_SIGNER",
                          "a.zid", "p_ab_k2", "s_pq.zid",
                          "THRESHOLD_DUPLICATE_SIGNER");
    const int ab[] = { 0, 1, -1 };
    failures += rt_check(rt_pins(fx, "p_k99999", ab, "threshold 99999\n"),
                         "threshold 99999 pin file");
    failures += rt_expect(fx, "threshold 99999 is refused (PIN_FILE_INVALID)",
                          "a.zid", "p_k99999", "b.zid", "PIN_FILE_INVALID");
    bool ok = true;
    for (int i = 0; ok && i < 8; i++) {
        snprintf(files[i], sizeof(files[i]), "m%d.zid", i);
        ok = rt_doc(fx, i == 0 ? 1 : 3 + i, "z23", "1.0", fx->root, files[i]);
        if (i == 0)
            continue;
        if (i < 7) {
            strcat(seven, ",");
            strcat(seven, files[i]);
        }
    }
    failures += rt_check(ok, "nine distinct signers");
    char seven_all[640];
    snprintf(seven_all, sizeof(seven_all), "%s%s", files[0], seven);
    snprintf(all, sizeof(all), "%s%s,%s", files[0], seven, files[7]);
    failures += rt_expect(fx, "a primary plus 7 cosigners (8 docs) is not "
                          "over the cap", "a.zid", "p_ab_k2", seven_all, "");
    failures += rt_expect(fx, "a primary plus 8 cosigners (9 docs) is "
                          "TOO_MANY_DOCS", "a.zid", "p_ab_k2",
                          all, "TOO_MANY_DOCS");
    return failures;
}

/* `zcode release verify` runs the same gate: K=2 with two sibling docs
 * accepts and reports the counts; with one doc it is refused. */
static int rt_verify(const struct rt_fx *fx)
{
    int failures = 0;
    for (int pass = 0; pass < 2; pass++) {
        struct json_value in;
        struct zcl_command_request req;
        struct zcl_command_reply reply;
        char a[PATH_MAX], b[PATH_MAX], pins[PATH_MAX];
        snprintf(a, sizeof(a), "%s/a.zid", fx->dir);
        snprintf(b, sizeof(b), "%s/b.zid", fx->dir);
        snprintf(pins, sizeof(pins), "%s/p_ab_k2", fx->dir);
        json_init(&in);
        json_set_object(&in);
        json_push_kv_str(&in, "file", a);
        json_push_kv_str(&in, "pin_file", pins);
        if (pass == 0)
            json_push_kv_str(&in, "cosigs", b);
        memset(&req, 0, sizeof(req));
        req.input = &in;
        zcl_command_reply_init(&reply, "zcl.release_threshold_verify.v1");
        zcl_native_handle_zcode_release_verify(&req, &reply);
        const struct json_value *m = json_get(&reply.data, "signers_matched");
        bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED;
        if (pass == 0)
            failures += rt_check(ok && m && json_get_int(m) == 2,
                                 "zcode release verify: K=2 with two docs "
                                 "accepts (signers_matched 2)");
        else
            failures += rt_check(!ok && strcmp(reply.error.code,
                                               "THRESHOLD_SINGLE_DOC") == 0,
                                 "zcode release verify: K=2 with one doc is "
                                 "THRESHOLD_SINGLE_DOC");
        zcl_command_reply_free(&reply);
        json_free(&in);
    }
    return failures;
}

/* A non-string cosigs is BAD_COSIGS in zcode release verify even with no
 * pin file and no threshold. */
static int rt_bad_cosigs(const struct rt_fx *fx)
{
    struct json_value in;
    struct zcl_command_request req;
    struct zcl_command_reply reply;
    char a[PATH_MAX];
    snprintf(a, sizeof(a), "%s/a.zid", fx->dir);
    json_init(&in);
    json_set_object(&in);
    json_push_kv_str(&in, "file", a);
    json_push_kv_int(&in, "cosigs", 7);
    memset(&req, 0, sizeof(req));
    req.input = &in;
    zcl_command_reply_init(&reply, "zcl.release_threshold_cosigs.v1");
    zcl_native_handle_zcode_release_verify(&req, &reply);
    int failures = rt_check(reply.status != ZCL_COMMAND_STATUS_PASSED &&
                                strcmp(reply.error.code, "BAD_COSIGS") == 0,
                            "zcode release verify: a non-string cosigs is "
                            "BAD_COSIGS with no threshold set");
    zcl_command_reply_free(&reply);
    json_free(&in);
    return failures;
}

/* Readers refuse anything but a regular file: a symlink (not followed) and a
 * FIFO (never blocks) are DOC_UNREADABLE / PIN_FILE_UNREADABLE. */
static int rt_io(const struct rt_fx *fx)
{
    int failures = 0;
    char a[PATH_MAX], link_doc[PATH_MAX], fifo[PATH_MAX], link_pins[PATH_MAX];
    char pins[PATH_MAX];
    struct release_pin_doc d;
    const char *code = NULL;
    snprintf(a, sizeof(a), "%s/a.zid", fx->dir);
    snprintf(pins, sizeof(pins), "%s/p_ab_k2", fx->dir);
    snprintf(link_doc, sizeof(link_doc), "%s/link.zid", fx->dir);
    snprintf(link_pins, sizeof(link_pins), "%s/link_pins", fx->dir);
    snprintf(fifo, sizeof(fifo), "%s/fifo.zid", fx->dir);
    failures += rt_check(symlink(a, link_doc) == 0 &&
                             symlink(pins, link_pins) == 0 &&
                             mkfifo(fifo, 0600) == 0,
                         "symlink and FIFO fixtures");
    failures += rt_check(!release_pin_read_any(link_doc, &d, &code) &&
                             strcmp(code, "DOC_UNREADABLE") == 0,
                         "a symlinked release doc is DOC_UNREADABLE");
    failures += rt_check(!release_pin_read_any(fifo, &d, &code) &&
                             strcmp(code, "DOC_UNREADABLE") == 0,
                         "a FIFO release doc is DOC_UNREADABLE, no hang");
    failures += rt_expect(fx, "a symlinked cosigner doc is DOC_UNREADABLE",
                          "a.zid", "p_ab_k2", "link.zid", "DOC_UNREADABLE");
    failures += rt_expect(fx, "a FIFO cosigner doc is DOC_UNREADABLE",
                          "a.zid", "p_ab_k2", "fifo.zid", "DOC_UNREADABLE");
    failures += rt_expect(fx, "a symlinked pin file is PIN_FILE_UNREADABLE",
                          "a.zid", "link_pins", "b.zid",
                          "PIN_FILE_UNREADABLE");
    failures += rt_expect(fx, "a FIFO pin file is PIN_FILE_UNREADABLE",
                          "a.zid", "fifo.zid", "b.zid",
                          "PIN_FILE_UNREADABLE");
    return failures;
}

int release_threshold_suite(void)
{
    struct rt_fx fx;
    int failures = 0;
    printf("\n=== release threshold (k-of-n) tests ===\n");
    if (!rt_init(&fx)) {
        printf("release_threshold: fixture... FAIL\n");
        return 1;
    }
    failures += rt_accept(&fx);
    failures += rt_refusals(&fx);
    failures += rt_more_negative(&fx);
    failures += rt_io(&fx);
    failures += rt_verify(&fx);
    failures += rt_bad_cosigs(&fx);
    char rm[PATH_MAX + 16];
    snprintf(rm, sizeof(rm), "rm -rf '%s'", fx.dir);
    TEST_DISCARD(system(rm));
    printf("=== RELEASE_THRESHOLD: %d failure(s) ===\n", failures);
    return failures;
}
