/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: signed intents, receipts, takeover, lost acks and push races.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#if !defined(_WIN32)


static bool dlx_receipt_step(const char *error, const char *signer)
{
    struct dlx_call c;
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c);
    if (error)
        ok = ok && !dlx_ok(&c) && dlx_err_code(&c) &&
             strcmp(dlx_err_code(&c), error) == 0;
    else
        ok = ok && dlx_ok(&c) && strcmp(dlx_str(&c, "state"), "landed") == 0 &&
             (!signer || strcmp(dlx_str(&c, "remote_signer"), signer) == 0);
    dlx_end(&c);
    return ok;
}

static bool dlx_receipt_tamper_one(struct dlx_rig *rig, const char *queue,
                                  const char *original, size_t len,
                                  const char *field)
{
    char key[80], altered[8192], observed[8192], remote[64];
    size_t got;
    memcpy(altered, original, len + 1);
    (void)snprintf(key, sizeof(key), "\"%s\":\"", field);
    char *value = strstr(altered, key);
    if (!value) return false;
    value += strlen(key);
    if (!((*value >= '0' && *value <= '9') || (*value >= 'a' && *value <= 'f')))
        return false;
    *value = *value == '0' ? '1' : '0';
    return dlx_write(queue, altered) && dlx_receipt_step("REMOTE_RECEIPT_INVALID", NULL) &&
        dlx_slurp(queue, observed, sizeof(observed), &got) && got == len &&
        memcmp(altered, observed, len) == 0 &&
        dlx_origin_main(rig, remote) && strcmp(remote, rig->tip) == 0;
}

static bool dlx_receipt_tamper_cases(void)
{
    struct dlx_rig rig;
    char queue[1400], marker[1400], original[8192], count[32];
    size_t len, got;
    bool ok = false;
    dlx_isolate("receipt_tamper");
    if (!dlx_signed_receipt_pending(&rig, queue, sizeof(queue), marker, sizeof(marker), true) ||
        !dlx_slurp(queue, original, sizeof(original) - 1, &len))
        goto done;
    original[len] = 0;
    const char *fields[] = { "remote_signature", "remote_signer", "remote_source" };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        if (!dlx_receipt_tamper_one(&rig, queue, original, len, fields[i]))
            goto done;
    }
    if (!dlx_write(queue, original) || !dlx_receipt_step(NULL, NULL))
        goto done;
    ok = dlx_slurp(marker, count, sizeof(count), &got) && got == 8 &&
         memcmp(count, "invoked\n", 8) == 0;
done:
    unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
    dlx_restore();
    return ok;
}

static bool dlx_takeover_original_signer(const char *a_hex)
{
    char land[1200], path[1400], wire[8192];
    size_t len;
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", land);
    struct json_value doc = {0};
    bool ok = dlx_slurp(path, wire, sizeof(wire), &len) &&
        json_read(&doc, wire, len) && doc.type == JSON_OBJ;
    const char *signer = json_get_str(json_get(&doc, "publication_signer"));
    ok = ok && signer && strcmp(signer, a_hex) == 0;
    json_free(&doc);
    return ok;
}

static bool dlx_takeover_landed(const char *a_hex, const char *b_hex)
{
    struct dlx_call c;
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && dlx_ok(&c) &&
        strcmp(dlx_str(&c, "state"), "landed") == 0 &&
        strcmp(dlx_str(&c, "remote_signer"), b_hex) == 0;
    dlx_end(&c);
    return ok && dlx_takeover_original_signer(a_hex);
}

static bool dlx_takeover_trust(struct dlx_rig *rig, const char *queue,
                               const char *wire, size_t len,
                               const char *allow, const uint8_t a[32],
                               const uint8_t b[32])
{
    char observed[8192], remote[64], a_hex[65], b_hex[65], allow_text[80];
    size_t got;
    if (!dlx_receipt_step("PUBLICATION_INTENT_INVALID", NULL) ||
        !dlx_slurp(queue, observed, sizeof(observed), &got) || got != len ||
        memcmp(wire, observed, len) != 0 || !dlx_origin_main(rig, remote) ||
        strcmp(remote, rig->tip) != 0)
        return false;
    zcl_hex_encode(a, 32, a_hex);
    zcl_hex_encode(b, 32, b_hex);
    (void)snprintf(allow_text, sizeof(allow_text), "%s\n", a_hex);
    return dlx_write(allow, allow_text) && chmod(allow, 0600) == 0 &&
        dlx_takeover_landed(a_hex, b_hex);
}

static bool dlx_takeover_identity(uint8_t a[32], char *key, size_t key_cap,
                                  char *allow, size_t allow_cap)
{
    bool present = false;
    const char *why = NULL;
    return zcl_dev_proof_signer_public(a, &present, &why) && present &&
        zcl_dev_proof_signer_paths(key, key_cap, allow, allow_cap);
}

static bool dlx_receipt_receive_once(const char *marker)
{
    char count[32];
    size_t got;
    return dlx_slurp(marker, count, sizeof(count), &got) && got == 8 &&
        memcmp(count, "invoked\n", 8) == 0;
}

static bool dlx_receipt_different_signer(void)
{
    struct dlx_rig rig;
    char queue[1400], marker[1400], key[4096], allow[4096], backup[4160];
    char wire[8192];
    uint8_t a[32], b[32], signature[64];
    bool saved = false, ok = false;
    const char *why = NULL;
    size_t got, len;
    dlx_isolate("receipt_different_signer");
    if (!dlx_signed_receipt_pending(&rig, queue, sizeof(queue), marker, sizeof(marker), false) ||
        !dlx_slurp(queue, wire, sizeof(wire) - 1, &got))
        goto done;
    wire[got] = 0;
    len = got;
    if (!strstr(wire, "\"remote_signature\":\"\"") ||
        !dlx_takeover_identity(a, key, sizeof(key), allow, sizeof(allow)))
        goto done;
    if (snprintf(backup, sizeof(backup), "%s.fixture-saved", key) >= (int)sizeof(backup) ||
        rename(key, backup) != 0)
        goto done;
    saved = true;
    if (!zcl_dev_proof_signer_sign((const uint8_t *)"takeover", 8, b, signature, &why) ||
        memcmp(a, b, sizeof(a)) == 0 ||
        !dlx_takeover_trust(&rig, queue, wire, len, allow, a, b))
        goto done;
    /* B independently observes the remote and signs a new receipt while
     * trusting A's preserved publication intent; the push occurs once. */
    ok = dlx_receipt_receive_once(marker);
done:
    if (saved) {
        if (unlink(key) != 0 && errno != ENOENT)
            ok = false;
        if (rename(backup, key) != 0)
            ok = false;
    }
    unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
    dlx_restore();
    return ok;
}
#endif

/* These cases enter dl_escape through its production caller dl_encode_row.
 * No queue, clock, filesystem fixture or publication authority is involved. */
static int dlx_row_utf8_refuses(const char *name, const char *text, bool detail)
{
    int failures = 0;
    TEST(name) {
        char out[8192], unchanged[8192];
        size_t len = 123;
        memset(out, 'X', sizeof(out));
        memcpy(unchanged, out, sizeof(out));
        ASSERT(!zcl_native_dev_land_test_encode_text(text, detail, out,
                                                     sizeof(out), &len));
        ASSERT_EQ(len, 123);
        ASSERT(memcmp(out, unchanged, sizeof(out)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static bool dlx_row_text_roundtrips(const char *out, size_t len,
                                    const char *text, bool detail)
{
    struct json_value doc;
    json_init(&doc);
    bool ok = json_read(&doc, out, len);
    const char *decoded = json_get_str(json_get(&doc, detail ? "detail" : "note"));
    ok = ok && decoded && strcmp(decoded, text) == 0;
    json_free(&doc);
    return ok;
}

static bool dlx_row_empty_capacity(bool detail)
{
    char out[8192];
    size_t len = 0;
    if (!zcl_native_dev_land_test_encode_text("", detail, out, sizeof(out), &len))
        return false;
    if (len >= sizeof(out))
        return false;
    size_t exact = len + 1;
    if (!zcl_native_dev_land_test_encode_text("", detail, out, exact, &len))
        return false;
    size_t unchanged = len;
    if (zcl_native_dev_land_test_encode_text("", detail, out, exact - 1, &len) ||
        len != unchanged)
        return false;
    if (zcl_native_dev_land_test_encode_text("", detail, out, 0, &len) ||
        len != unchanged)
        return false;
    if (zcl_native_dev_land_test_encode_text("", detail, NULL, 1, &len))
        return false;
    return len == unchanged;
}

static int dlx_row_utf8_valid(bool detail)
{
    int failures = 0;
    TEST("land: row encoding preserves UTF-8 and JSON escapes with exact capacity") {
        static const char text[] =
            "\"\\\n\r\t\b\f\x01\x1f\x7f"
            "\xc2\x80\xdf\xbf\xe0\xa0\x80\xed\x9f\xbf"
            "\xee\x80\x80\xef\xbf\xbf\xf0\x90\x80\x80\xf4\x8f\xbf\xbf";
        static const char escaped[] =
            "\\\"\\\\\\n\\r\\t\\u0008\\u000c\\u0001\\u001f\x7f"
            "\xc2\x80\xdf\xbf\xe0\xa0\x80\xed\x9f\xbf"
            "\xee\x80\x80\xef\xbf\xbf\xf0\x90\x80\x80\xf4\x8f\xbf\xbf";
        char out[8192], exact[8192];
        size_t len = 0, got = 0;
        ASSERT(zcl_native_dev_land_test_encode_text(text, detail, out,
                                                    sizeof(out), &len));
        ASSERT(strstr(out, escaped) != NULL);
        ASSERT_EQ(len, strlen(out));
        ASSERT(dlx_row_text_roundtrips(out, len, text, detail));
        ASSERT(len + 1 < sizeof(exact));
        ASSERT(zcl_native_dev_land_test_encode_text(text, detail, exact,
                                                    len + 1, &got));
        ASSERT_EQ(got, len);
        ASSERT_STR_EQ(exact, out);
        got = 123;
        ASSERT(!zcl_native_dev_land_test_encode_text(text, detail, exact,
                                                     len, &got));
        ASSERT_EQ(got, 123);
        ASSERT(dlx_row_empty_capacity(detail));
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_row_utf8_dense_detail(void)
{
    int failures = 0;
    TEST("land: a full control-byte detail still fits its escaped row buffer") {
        char text[1024], out[8192], expected[1023 * 6 + 1];
        size_t len = 0;
        memset(text, '\x01', sizeof(text) - 1);
        text[sizeof(text) - 1] = '\0';
        for (size_t i = 0; i < sizeof(text) - 1; ++i)
            memcpy(expected + i * 6, "\\u0001", 6);
        expected[sizeof(expected) - 1] = '\0';
        ASSERT(zcl_native_dev_land_test_encode_text(text, true, out,
                                                    sizeof(out), &len));
        ASSERT(strstr(out, expected) != NULL);
        ASSERT_EQ(len, strlen(out));
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_row_utf8_cases(void)
{
    static const struct { const char *name; const char *text; } cases[] = {
        { "land: refuse stray continuation in a row", "a\x80" },
        { "land: refuse overlong two-byte UTF-8 in a row", "\xc0\xaf" },
        { "land: refuse C1 overlong UTF-8 in a row", "\xc1\xbf" },
        { "land: refuse overlong three-byte UTF-8 in a row", "\xe0\x80\xaf" },
        { "land: refuse overlong four-byte UTF-8 in a row", "\xf0\x80\x80\xaf" },
        { "land: refuse a UTF-16 surrogate in a row", "\xed\xa0\x80" },
        { "land: refuse a scalar above U+10FFFF in a row", "\xf4\x90\x80\x80" },
        { "land: refuse an illegal lead byte in a row", "\xff" },
        { "land: refuse F5 lead byte in a row", "\xf5\x80\x80\x80" },
        { "land: refuse an illegal lead after a prefix in a row", "prefix\xff" },
        { "land: refuse bad two-byte continuation in a row", "\xc2" "A" },
        { "land: refuse bad continuation in a row", "\xe2(\xa1" },
        { "land: refuse truncated two-byte UTF-8 in a row", "\xc2" },
        { "land: refuse truncated three-byte UTF-8 in a row", "\xe2\x82" },
        { "land: refuse truncated four-byte UTF-8 in a row", "\xf0\x9f\x92" }
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        failures += dlx_row_utf8_refuses(cases[i].name, cases[i].text, false);
        failures += dlx_row_utf8_refuses(cases[i].name, cases[i].text, true);
    }
    failures += dlx_row_utf8_valid(false);
    failures += dlx_row_utf8_valid(true);
    failures += dlx_row_utf8_dense_detail();
    return failures;
}

int test_dev_land_receipt_adversarial(void)
{
    int failures = dlx_row_utf8_cases();
#if !defined(_WIN32)
    TEST("land: tampered persisted remote receipts refuse without redispatch") {
        ASSERT(dlx_receipt_tamper_cases());
        PASS();
    } _test_next:;
#endif
    return failures;
}

int test_dev_land_signer_takeover(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: another signer resumes only with receiver-local trust") {
        ASSERT(dlx_receipt_different_signer());
        PASS();
    } _test_next:;
#endif
    return failures;
}

int test_dev_land_signed_tamper(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: tampered signed intent refuses before remote mutation") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], land[1200], path[1400];
        char wire[8192];
        size_t len = 0;
        dlx_isolate("signed_tamper");
        ASSERT(dlx_rig_make(&rig, "signed_tamper_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(land, sizeof(land));
        (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
        ASSERT(dlx_slurp(path, wire, sizeof(wire) - 1, &len));
        wire[len] = '\0';
        char *field = strstr(wire, "\"publication_signature\":\"");
        ASSERT(field != NULL);
        field += strlen("\"publication_signature\":\"");
        ASSERT(*field == '0' || (*field >= '1' && *field <= '9') ||
               (*field >= 'a' && *field <= 'f'));
        *field = *field == '0' ? '1' : '0';
        ASSERT(dlx_write(path, wire));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_INTENT_INVALID");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

int test_dev_land_signed_stale(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: signed pair rejects a moved base and retains successor work") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], stranger[64], remote[64];
        dlx_isolate("signed_stale");
        ASSERT(dlx_rig_make(&rig, "signed_stale_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        const char *branch[] = { "checkout", "--quiet", "-B", "side", base,
                                 NULL };
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "stranger.txt", "other\n", stranger));
        ASSERT(dlx_git(rig.clone, push) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "queued");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, stranger);
        ASSERT(dlx_queue_has_one());
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

int test_dev_land_signed_recovery(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: signed remote recovery records receipt without replaying push") {
        struct dlx_rig rig;
        struct dlx_call c;
        char land[1200], wt[1400], wrapper[1400], marker[1400];
        char script[3000];
        dlx_isolate("signed_recovery");
        ASSERT(dlx_rig_make(&rig, "signed_recovery_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(land, sizeof(land));
        (void)snprintf(wt, sizeof(wt), "%s/wt", land);
        (void)snprintf(wrapper, sizeof(wrapper), "%s/refuse-replay", land);
        (void)snprintf(marker, sizeof(marker), "%s/replay-attempted", land);
        (void)snprintf(script, sizeof(script),
                       "#!/bin/sh\nprintf 'attempted\\n' > '%s'\nexit 91\n",
                       marker);
        ASSERT(dlx_write(wrapper, script));
        ASSERT(chmod(wrapper, 0700) == 0);
        const char *intercept[] = { "config", "remote.origin.receivepack",
                                    wrapper, NULL };
        ASSERT(dlx_git(wt, intercept) == 0);
        char update[128];
        (void)snprintf(update, sizeof(update), "%s:refs/heads/main", rig.tip);
        const char *remote_effect[] = { "fetch", "--quiet", rig.clone,
                                        update, NULL };
        ASSERT(dlx_git(rig.bare, remote_effect) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT(strlen(dlx_str(&c, "remote_signature")) == 128);
        ASSERT(!dlx_file_exists(marker));
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

int test_dev_land_new_source_precheck(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: a range that adds a compiled source is told apart from one that edits a file or adds anything else") {
        struct dlx_rig rig;
        char base[64], edit[64], added[64], header[64];
        dlx_isolate("new_source_precheck");
        ASSERT(dlx_rig_make(&rig, "new_source_precheck_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        const char *onto[] = { "checkout", "--quiet", "-B", "probe", base,
                               NULL };
        ASSERT(dlx_git(rig.clone, onto) == 0);
        ASSERT(dlx_commit(rig.clone, "notes.md", "prose\n", edit));
        ASSERT(dlx_commit(rig.clone, "module.h", "int f(void);\n", header));
        ASSERT(dlx_commit(rig.clone, "module.c", "int f(void){return 0;}\n",
                          added));
        ASSERT(zcl_native_dev_land_test_range_adds_source(rig.clone, base,
                                                          edit) == 0);
        ASSERT(zcl_native_dev_land_test_range_adds_source(rig.clone, base,
                                                          header) == 0);
        ASSERT(zcl_native_dev_land_test_range_adds_source(rig.clone, base,
                                                          added) == 1);
        /* The file exists on both sides: an edit, not an addition. */
        ASSERT(zcl_native_dev_land_test_range_adds_source(rig.clone, added,
                                                          added) == 0);
        /* A pair git cannot name is never read as "nothing added". */
        ASSERT(zcl_native_dev_land_test_range_adds_source(
                   rig.clone, base,
                   "0123456789abcdef0123456789abcdef01234567") == -1);
        ASSERT(zcl_native_dev_land_test_range_adds_source(rig.clone, "main",
                                                          added) == -1);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

int test_dev_land_drive_producer_reproof(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: a drive whose binary is not the candidate's builds the producer in the landing worktree and proves with it") {
        char root[512], make_ok[1400], make_bad[1400], script[4000];
        char log[1400], seen[2048], want[1800], why[256] = "";
        size_t seen_len = 0;
        test_make_tmpdir(root, sizeof(root), "dev_land", "drive_producer_wt");
        ASSERT(zcl_native_dev_land_test_producer_stale(
            "proof_producer_source_mismatch"));
        ASSERT(zcl_native_dev_land_test_producer_stale(
            "failed exact proof: proof_producer_source_mismatch"));
        ASSERT(!zcl_native_dev_land_test_producer_stale("lint"));
        ASSERT(!zcl_native_dev_land_test_producer_stale(NULL));
        (void)snprintf(make_ok, sizeof(make_ok), "%s/fake-make", root);
        (void)snprintf(make_bad, sizeof(make_bad), "%s/fake-make-bad", root);
        (void)snprintf(log, sizeof(log), "%s/producer-argv", root);
        /* argv: -jN -C <root> dev-bin. The built "producer" records how it
         * was called. */
        (void)snprintf(script, sizeof(script),
                       "#!/bin/sh\n"
                       "[ \"$2\" = -C ] && [ \"$4\" = dev-bin ] || exit 64\n"
                       "mkdir -p \"$3/build/bin\" || exit 65\n"
                       "printf '%%s\\n' '#!/bin/sh' "
                       "'printf \"%%s \" \"$@\" > \"%s\"' "
                       "'exit 7' > \"$3/build/bin/z23-dev\" || exit 66\n"
                       "chmod 700 \"$3/build/bin/z23-dev\"\n", log);
        ASSERT(dlx_write(make_ok, script));
        ASSERT(chmod(make_ok, 0700) == 0);
        ASSERT(dlx_write(make_bad,
                         "#!/bin/sh\necho 'boom: no rule' >&2\nexit 2\n"));
        ASSERT(chmod(make_bad, 0700) == 0);
        /* A build that fails names itself and runs no proof. */
        ASSERT(zcl_native_dev_land_test_producer_reproof(
                   root, "1111111111111111111111111111111111111111",
                   "2222222222222222222222222222222222222222", make_bad, why,
                   sizeof(why)) == -1);
        ASSERT(why[0] != '\0');
        ASSERT(!dlx_file_exists(log));
        /* A built producer is run on the exact pair and root; its verdict
         * (here a failing exit) is the proof's to settle, not the drive's. */
        ASSERT(zcl_native_dev_land_test_producer_reproof(
                   root, "1111111111111111111111111111111111111111",
                   "2222222222222222222222222222222222222222", make_ok, why,
                   sizeof(why)) == 1);
        ASSERT(dlx_slurp(log, seen, sizeof(seen) - 1, &seen_len));
        seen[seen_len] = '\0';
        (void)snprintf(want, sizeof(want),
                       "dev proof step --root=%s "
                       "--local_commit=1111111111111111111111111111111111111111 "
                       "--remote_base=2222222222222222222222222222222222222222 ",
                       root);
        ASSERT_STR_EQ(seen, want);
        PASS();
    }
_test_next:;
#endif
    return failures;
}

int test_dev_land_signed_lost_ack(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: a lost signed push is re-sent only while main is unmoved and attempts remain; a moved base requeues a successor") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], land[1200], wt[1400];
        char wrapper[1400], marker[1400], script[3000], attempts[128];
        size_t attempts_len = 0;
        dlx_isolate("signed_lost_ack");
        ASSERT(dlx_rig_make(&rig, "signed_lost_ack_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(land, sizeof(land));
        (void)snprintf(wt, sizeof(wt), "%s/wt", land);
        (void)snprintf(wrapper, sizeof(wrapper), "%s/lose-ack", land);
        (void)snprintf(marker, sizeof(marker), "%s/dispatch-count", land);
        (void)snprintf(script, sizeof(script),
                       "#!/bin/sh\nprintf 'attempted\\n' >> '%s'\nexit 91\n",
                       marker);
        ASSERT(dlx_write(wrapper, script));
        ASSERT(chmod(wrapper, 0700) == 0);
        const char *intercept[] = { "config", "remote.origin.receivepack",
                                    wrapper, NULL };
        ASSERT(dlx_git(wt, intercept) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
        ASSERT_STR_EQ(dlx_str(&c, "observed_remote_tip"), base);
        ASSERT_STR_EQ(dlx_str(&c, "head_commit"), rig.tip);
        ASSERT_STR_EQ(dlx_str(&c, "dispatch_state"), "unknown");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        ASSERT(dlx_slurp(marker, attempts, sizeof(attempts), &attempts_len));
        ASSERT(attempts_len == strlen("attempted\n"));
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *steer = json_get(&c.reply.data, "steer");
        const struct json_value *inflight =
            json_get(&c.reply.data, "in_flight");
        ASSERT(steer != NULL);
        ASSERT(inflight != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(inflight, "acceptance_state")),
                      "unknown");
        ASSERT_STR_EQ(json_get_str(json_get(inflight, "dispatch_state")),
                      "unknown");
        ASSERT_STR_EQ(json_get_str(json_get(inflight, "detail")),
                      "signed push outcome unknown; await independent remote receipt");
        ASSERT_STR_EQ(json_get_str(json_get(steer,
                                          "first_missing_transition")),
                      "remote_receipt");
        dlx_end(&c);
        /* Main is unmoved and the head is absent, so the dispatch did not
         * apply: each later step sends the same compare-and-swap again,
         * one per attempt the row has left, and then stops asking. */
        for (size_t sent = 2; sent <= 4; sent++) {
            size_t want = sent > 3 ? 3 : sent;
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
            ASSERT_STR_EQ(dlx_str(&c, "dispatch_state"), "unknown");
            dlx_end(&c);
            ASSERT(dlx_origin_main(&rig, remote));
            ASSERT_STR_EQ(remote, base);
            ASSERT(dlx_slurp(marker, attempts, sizeof(attempts),
                             &attempts_len));
            ASSERT(attempts_len == want * strlen("attempted\n"));
        }
        char sibling[64];
        const char *branch[] = { "checkout", "--quiet", "-B", "side", base,
                                 NULL };
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "side.txt", "other\n", sibling));
        char update_side[128];
        (void)snprintf(update_side, sizeof(update_side),
                       "%s:refs/heads/main", sibling);
        const char *fetch_side[] = { "fetch", "--quiet", rig.clone,
                                     update_side, NULL };
        ASSERT(dlx_git(rig.bare, fetch_side) == 0);
        /* Base moved and the head is provably absent from the fresh
         * observation: the exact signed pair can never fast-forward onto
         * the moved main, so the row requeues as a successor instead of
         * waiting forever on a receipt that can never arrive.  The exact
         * pair is not sent onto a moved base (the count stays at 3). */
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "queued");
        ASSERT(dlx_int(&c, "predecessor_seq") == 1);
        dlx_end(&c);
        ASSERT(dlx_slurp(marker, attempts, sizeof(attempts), &attempts_len));
        ASSERT(attempts_len == 3 * strlen("attempted\n"));
        /* Drive the successor to a real landing: lift the lose-ack
         * intercept, rebase+prove, attach the fresh pair, push. */
        const char *restore[] = { "config", "--unset",
                                  "remote.origin.receivepack", NULL };
        ASSERT(dlx_git(wt, restore) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        dlx_end(&c);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 2);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT(strlen(dlx_str(&c, "remote_signature")) == 128);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT(strcmp(remote, base) != 0);
        ASSERT(strcmp(remote, sibling) != 0);
        ASSERT(dlx_slurp(marker, attempts, sizeof(attempts), &attempts_len));
        ASSERT(attempts_len == 3 * strlen("attempted\n"));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

#if !defined(_WIN32)
static bool dlx_sibling(const struct dlx_rig *rig, const char *base,
                        const char *ref, char out[64]);

/* Attach a signed intent to a proven pair and make the next push lose its
 * acknowledgement. `marker` counts receive-pack dispatches. With `racer`,
 * a sibling of base wins remote main inside that lost dispatch. */
bool dlx_signed_push_lossy(struct dlx_rig *rig, const char *tag,
                                  char base[64], char wt[1400],
                                  char marker[1400], char racer[64])
{
    struct dlx_call c;
    char land[1200], wrapper[1400], script[4000], extra[1600] = "";
    if (!dlx_attach_proven_pair(rig, tag, base))
        return false;
    dlx_begin(&c, "attach");
    (void)json_push_kv_int(&c.input, "seq", 1);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    if (racer) {
        ok = ok && dlx_sibling(rig, base, "refs/heads/side", racer);
        (void)snprintf(extra, sizeof(extra),
                       "git --git-dir='%s' update-ref refs/heads/main %s %s "
                       "|| exit 92\n", rig->bare, racer, base);
    }
    dlx_landdir(land, sizeof(land));
    (void)snprintf(wt, 1400, "%s/wt", land);
    (void)snprintf(wrapper, sizeof(wrapper), "%s/lose-ack", land);
    (void)snprintf(marker, 1400, "%s/dispatch-count", land);
    (void)snprintf(script, sizeof(script),
                   "#!/bin/sh\nprintf 'attempted\\n' >> '%s'\n%sexit 91\n",
                   marker, extra);
    const char *intercept[] = { "config", "remote.origin.receivepack",
                                wrapper, NULL };
    return ok && dlx_write(wrapper, script) && chmod(wrapper, 0700) == 0 &&
           dlx_git(wt, intercept) == 0;
}

/* Commit a sibling of `base` in the clone and publish it on the bare
 * remote as `ref`. */
static bool dlx_sibling(const struct dlx_rig *rig, const char *base,
                        const char *ref, char out[64])
{
    char update[160];
    const char *branch[] = { "checkout", "--quiet", "-B", "side", base,
                             NULL };
    if (dlx_git(rig->clone, branch) != 0 ||
        !dlx_commit(rig->clone, "side.txt", "other\n", out))
        return false;
    (void)snprintf(update, sizeof(update), "%s:%s", out, ref);
    const char *fetch[] = { "fetch", "--quiet", rig->clone, update, NULL };
    return dlx_git(rig->bare, fetch) == 0;
}

static bool dlx_dispatched_once(const char *marker)
{
    char attempts[128];
    size_t len = 0;
    return dlx_slurp(marker, attempts, sizeof(attempts), &len) &&
           len == strlen("attempted\n");
}

/* The successor carries no publication and the land log names the settled
 * refusal against the observed sibling. */
static bool dlx_refused_successor(const struct dlx_call *c,
                                  const char *sibling)
{
    char queue[16384], log[65536], want[160];
    size_t qlen = 0, llen = 0;
    const char *log_path = dlx_str(c, "log_path");
    if (!dlx_queue_bytes(queue, sizeof(queue), &qlen) ||
        !strstr(queue, "\"publication_signature\":\"\"") ||
        !log_path || !dlx_slurp(log_path, log, sizeof(log) - 1, &llen))
        return false;
    log[llen] = '\0';
    (void)snprintf(want, sizeof(want),
                   "signed push refused: main moved to %s without head; "
                   "successor seq=1", sibling);
    return strstr(log, want) != NULL;
}
#endif

int test_dev_land_signed_lost_race(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: signed push checkpoint settles as refused once main moves to a sibling") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], wt[1400], marker[1400], sibling[64];
        char upload_pack[1400];
        dlx_isolate("signed_lost_race");
        ASSERT(dlx_signed_push_lossy(&rig, "signed_lost_race", base, wt,
                                     marker, NULL));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
        ASSERT_STR_EQ(dlx_str(&c, "observed_remote_tip"), base);
        dlx_end(&c);
        ASSERT(dlx_dispatched_once(marker));
        ASSERT(dlx_sibling(&rig, base, "refs/heads/main", sibling));
        /* Without a fresh observation the moved remote is not evidence. */
        (void)snprintf(upload_pack, sizeof(upload_pack), "%s.upload-pack",
                       rig.bare);
        ASSERT(dlx_write(upload_pack, "#!/bin/sh\nexit 75\n"));
        ASSERT(chmod(upload_pack, 0700) == 0);
        const char *blind[] = { "config", "remote.origin.uploadpack",
                                upload_pack, NULL };
        const char *see[] = { "config", "--unset", "remote.origin.uploadpack",
                              NULL };
        ASSERT(dlx_git(wt, blind) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "REMOTE_OBSERVATION_UNAVAILABLE");
        dlx_end(&c);
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
        dlx_end(&c);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *flight = json_get(&c.reply.data, "in_flight");
        ASSERT(flight != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(flight, "phase")), "push");
        dlx_end(&c);
        ASSERT(dlx_git(wt, see) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "queued");
        ASSERT_EQ(dlx_int(&c, "predecessor_seq"), 1);
        ASSERT(dlx_refused_successor(&c, sibling));
        dlx_end(&c);
        ASSERT(dlx_dispatched_once(marker));
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, sibling);
        ASSERT(dlx_queue_has_one());
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

int test_dev_land_signed_lost_ack_resend(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: a lost signed push on a quiet main lands on the next step as the same row and pair") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], wt[1400], marker[1400];
        dlx_isolate("signed_lost_ack_resend");
        ASSERT(dlx_signed_push_lossy(&rig, "signed_lost_ack_resend", base,
                                     wt, marker, NULL));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
        dlx_end(&c);
        ASSERT(dlx_dispatched_once(marker));
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        /* The remote answers again. Nothing else moved: no successor, no
         * second proof, no second signature — the next step is the push. */
        const char *restore[] = { "config", "--unset",
                                  "remote.origin.receivepack", NULL };
        ASSERT(dlx_git(wt, restore) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT(dlx_int(&c, "seq") == 1);
        ASSERT_STR_EQ(dlx_str(&c, "tip_pushed"), rig.tip);
        ASSERT(strlen(dlx_str(&c, "remote_signature")) == 128);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        ASSERT(dlx_dispatched_once(marker));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

int test_dev_land_signed_push_lost_race(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: signed push that loses the race while dispatching requeues as successor") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], wt[1400], marker[1400], sibling[64];
        dlx_isolate("signed_push_lost_race");
        ASSERT(dlx_signed_push_lossy(&rig, "signed_push_lost_race", base, wt,
                                     marker, sibling));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "queued");
        ASSERT_EQ(dlx_int(&c, "predecessor_seq"), 1);
        ASSERT(dlx_refused_successor(&c, sibling));
        dlx_end(&c);
        ASSERT(dlx_dispatched_once(marker));
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, sibling);
        ASSERT(dlx_queue_has_one());
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

int test_dev_land_cancel_push_refused(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: cancel drops a push checkpoint settled as refused") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], sibling[64], wire[8192];
        size_t used = 0;
        dlx_isolate("cancel_push_refused");
        ASSERT(dlx_attach_proven_pair(&rig, "cancel_push_refused", base));
        ASSERT(dlx_queue_bytes(wire, sizeof(wire), &used));
        char *phase = strstr(wire, "\"phase\":\"prove\"");
        ASSERT(phase != NULL);
        memcpy(phase, "\"phase\":\"push\" ", 15);
        char land[1200], path[1400];
        dlx_landdir(land, sizeof(land));
        (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
        ASSERT(dlx_write(path, wire));
        ASSERT(dlx_sibling(&rig, base, "refs/heads/main", sibling));
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "cancelled");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, sibling);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(json_get(&c.reply.data, "in_flight") == NULL);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

#if !defined(_WIN32)
/* Attach a signed intent to a proven pair and make the bare remote's
 * pre-receive hook decline every update with GitHub's GH007 text. */
static bool dlx_declined_rig(struct dlx_rig *rig, const char *tag,
                             char base[64], char wt[1400])
{
    struct dlx_call c;
    char land[1200], hook[1400];
    if (!dlx_attach_proven_pair(rig, tag, base))
        return false;
    dlx_begin(&c, "attach");
    (void)json_push_kv_int(&c.input, "seq", 1);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    dlx_landdir(land, sizeof(land));
    (void)snprintf(wt, 1400, "%s/wt", land);
    (void)snprintf(hook, sizeof(hook), "%s/hooks/pre-receive", rig->bare);
    const char *mail[] = { "config", "user.email", "land@z23.invalid", NULL };
    return ok && dlx_git(wt, mail) == 0 &&
           dlx_write(hook, "#!/bin/sh\necho 'error: GH007: Your push would "
                           "publish a private email address.' >&2\nexit 1\n") &&
           chmod(hook, 0700) == 0;
}
#endif

int test_dev_land_push_declined(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: a push the server declined settles as PUSH_DECLINED_PRIVATE_EMAIL, fails the row and frees the queue") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], wt[1400];
        dlx_isolate("push_declined");
        ASSERT(dlx_declined_rig(&rig, "push_declined", base, wt));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "failed");
        ASSERT_STR_EQ(dlx_str(&c, "code"), "PUSH_DECLINED_PRIVATE_EMAIL");
        ASSERT(strstr(dlx_str(&c, "next_action"), "noreply") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "[remote rejected]") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "://") == NULL);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        /* The drive reads the settled row as failed, not as a wedge. */
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(json_get(&c.reply.data, "in_flight") == NULL);
        dlx_end(&c);
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "SEQ_UNKNOWN");
        dlx_end(&c);
        /* The next row proceeds. */
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") != 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
    TEST("land: cancel drops a push checkpoint whose persisted diagnostic shows a declined update") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], wire[8192], wt[1400], land[1200], path[1400], text[1024];
        size_t used = 0;
        dlx_isolate("push_declined_cancel");
        ASSERT(dlx_declined_rig(&rig, "push_declined_cancel", base, wt));
        ASSERT(dlx_queue_bytes(wire, sizeof(wire), &used));
        char *phase = strstr(wire, "\"phase\":\"prove\"");
        ASSERT(phase != NULL);
        memcpy(phase, "\"phase\":\"push\" ", 15);
        dlx_landdir(land, sizeof(land));
        (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
        ASSERT(dlx_write(path, wire));
        for (int attempt = 1; attempt <= 3; attempt++) {
            (void)snprintf(path, sizeof(path), "%s/logs/push-1-a%d.diagnostic",
                           land, attempt);
            (void)snprintf(text, sizeof(text),
                "publication diagnostic v1\nseq=1 attempt=%d target=t\n"
                "base=%s head=%s\nargv=git push\n"
                "exit_observed=1 exit_code=1 timed_out=0 eof=1 overflow=0 bytes=99\n"
                "remote: error: GH007: private\n"
                " ! [remote rejected] %s -> main (pre-receive hook declined)\n"
                "\nEND publication diagnostic\n", attempt, base, rig.tip, rig.tip);
            ASSERT(dlx_write(path, text));
        }
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "cancelled");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
    TEST("land: a transport failure that prints GH007 text but no status line stays PUSH_OUTCOME_UNKNOWN") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], wt[1400], marker[1400];
        dlx_isolate("push_transport");
        ASSERT(dlx_signed_push_lossy(&rig, "push_transport", base, wt, marker,
                                     NULL));
        const char *noisy = "#!/bin/sh\necho 'remote: error: GH007: Your push "
            "would publish a private email address.' >&2\nexit 91\n";
        char land[1200], wrapper[1400];
        dlx_landdir(land, sizeof(land));
        (void)snprintf(wrapper, sizeof(wrapper), "%s/lose-ack", land);
        ASSERT(dlx_write(wrapper, noisy));
        ASSERT(chmod(wrapper, 0700) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
        dlx_end(&c);
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
    TEST("land: a commit whose identity differs from user.email is refused before any push") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], wt[1400], marker[1400];
        dlx_isolate("push_identity");
        ASSERT(dlx_signed_push_lossy(&rig, "push_identity", base, wt, marker,
                                     NULL));
        const char *mail[] = { "config", "user.email", "noreply@z23.invalid",
                               NULL };
        ASSERT(dlx_git(wt, mail) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_IDENTITY_PRIVATE");
        dlx_end(&c);
        ASSERT(!dlx_file_exists(marker));
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(json_get(&c.reply.data, "in_flight") == NULL);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

int test_dev_land_signed_publisher_death(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: publisher death after signed remote mutation recovers receipt") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], hook[1400], wrapper[1400], marker[1400];
        char received[32];
        size_t received_len = 0;
        int child_status = 0;
        dlx_isolate("signed_publisher_death");
        ASSERT(dlx_rig_make(&rig, "signed_publisher_death_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        (void)snprintf(hook, sizeof(hook), "%s/hooks/post-receive", rig.bare);
        (void)snprintf(wrapper, sizeof(wrapper), "%s.receive-pack", rig.bare);
        (void)snprintf(marker, sizeof(marker),
                       "%s/hooks/receive-invocations", rig.bare);
        ASSERT(dlx_write(wrapper, "#!/bin/sh\n"
            "printf 'invoked\\n' >> \"$1/hooks/receive-invocations\" || exit 73\n"
            "exec git-receive-pack \"$@\"\n"));
        ASSERT(chmod(wrapper, 0700) == 0);
        char land[1200], wt[1400];
        dlx_landdir(land, sizeof(land));
        (void)snprintf(wt, sizeof(wt), "%s/wt", land);
        const char *intercept[] = { "config", "remote.origin.receivepack",
                                    wrapper, NULL };
        ASSERT(dlx_git(wt, intercept) == 0);
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            struct dlx_call cc;
            char script[256];
            (void)setsid(); /* see dlx_wait_publisher */
            (void)alarm(30);
            (void)snprintf(script, sizeof(script),
                           "#!/bin/sh\nkill -KILL %ld\n", (long)getpid());
            if (!dlx_write(hook, script) || chmod(hook, 0700) != 0)
                _exit(2);
            dlx_begin(&cc, "step");
            (void)dlx_run(&cc);
            _exit(90);
        }
        ASSERT(dlx_wait_publisher(child, &child_status) == child);
        ASSERT(WIFSIGNALED(child_status) && WTERMSIG(child_status) == SIGKILL);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        ASSERT(dlx_slurp(marker, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 8);
        ASSERT(memcmp(received, "invoked\n", 8) == 0);
        ASSERT(unlink(hook) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT(strlen(dlx_str(&c, "remote_signature")) == 128);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        ASSERT(dlx_slurp(marker, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 8);
        ASSERT(memcmp(received, "invoked\n", 8) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

#if !defined(_WIN32)
bool dlx_is_ancestor(const char *dir, const char *ancestor,
                             const char *descendant)
{
    const char *args[] = { "merge-base", "--is-ancestor", ancestor,
                           descendant, NULL };
    return dlx_git(dir, args) == 0;
}

bool dlx_marker_lines(const char *marker, size_t want)
{
    char text[256];
    size_t len = 0;
    return dlx_slurp(marker, text, sizeof(text), &len) &&
           len == want * strlen("attempted\n");
}

/* Rewrite the dispatch interceptor installed by dlx_signed_push_lossy.
 * Every dispatch is counted; `body` runs next, and a body that falls
 * through exits like a lost acknowledgement. */
bool dlx_dispatch_script(const char *marker, const char *body)
{
    char land[1200], wrapper[1400], script[3000];
    dlx_landdir(land, sizeof(land));
    (void)snprintf(wrapper, sizeof(wrapper), "%s/lose-ack", land);
    (void)snprintf(script, sizeof(script),
                   "#!/bin/sh\nprintf 'attempted\\n' >> '%s'\n%s", marker, body);
    return dlx_write(wrapper, script) && chmod(wrapper, 0700) == 0;
}

/* CANONICAL_LIFECYCLE.md PUBLICATION: the intent is durable before any
 * remote ref mutation, and duplicate dispatch reconciles the existing
 * intent before any further mutation.  The publisher dies inside the first
 * dispatch, before the remote applied anything.  The durable pre-push
 * checkpoint forbids redispatch (the dead dispatch may have applied), so
 * with an unmoved main every later step reports the unknown outcome and
 * sends nothing.  The retained row settles as a refused successor only once
 * main moves without the head.  This pins the present policy, which is
 * narrower than CANONICAL_LIFECYCLE.md "sends the identical expected-base
 * update again": that resend happens only when the dispatch was recorded.
 * Here the publisher died between the pre-push checkpoint and that record,
 * so an orphaned push may still apply and the row stays UNKNOWN on an
 * unmoved base.  A change of that policy must change this test. */
int test_dev_land_signed_crash_before_push(void)
{
    int failures = 0;
    TEST("land: publisher death after the intent and before the push retains the intent and never dispatches blind") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], wt[1400], marker[1400], queue[16384];
        char sibling[64];
        size_t queue_len = 0;
        int child_status = 0;
        dlx_isolate("signed_crash_before_push");
        ASSERT(dlx_signed_push_lossy(&rig, "signed_crash_before_push", base,
                                     wt, marker, NULL));
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            struct dlx_call cc;
            char body[128];
            (void)setsid(); /* see dlx_wait_publisher */
            (void)alarm(30);
            (void)snprintf(body, sizeof(body), "kill -KILL %ld\nexit 91\n",
                           (long)getpid());
            if (!dlx_dispatch_script(marker, body))
                _exit(2);
            dlx_begin(&cc, "step");
            (void)dlx_run(&cc);
            _exit(90);
        }
        ASSERT(dlx_wait_publisher(child, &child_status) == child);
        ASSERT(WIFSIGNALED(child_status) && WTERMSIG(child_status) == SIGKILL);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        ASSERT(dlx_marker_lines(marker, 1));
        ASSERT(dlx_queue_bytes(queue, sizeof(queue), &queue_len));
        ASSERT(strstr(queue, "\"phase\":\"push\"") != NULL);
        ASSERT(strstr(queue, "\"publication_signature\":\"\"") == NULL);
        ASSERT(dlx_dispatch_script(marker, "exec git-receive-pack \"$@\"\n"));
        for (unsigned i = 0; i < 2; i++) {
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
            ASSERT_STR_EQ(dlx_str(&c, "observed_remote_tip"), base);
            ASSERT_STR_EQ(dlx_str(&c, "head_commit"), rig.tip);
            dlx_end(&c);
            ASSERT(dlx_origin_main(&rig, remote));
            ASSERT_STR_EQ(remote, base);
            ASSERT(dlx_marker_lines(marker, 1));
        }
        ASSERT(dlx_sibling(&rig, base, "refs/heads/main", sibling));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "queued");
        ASSERT_EQ(dlx_int(&c, "predecessor_seq"), 1);
        ASSERT(dlx_refused_successor(&c, sibling));
        dlx_end(&c);
        ASSERT(dlx_marker_lines(marker, 1));
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, sibling);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* CANONICAL_LIFECYCLE.md PUBLICATION: a moved target without the head is
 * never sent the stale pair.  A third party moves main after the intent is
 * signed and before the first dispatch: the fresh observation supersedes
 * the signed pair, logs the stale intent and requeues a successor that
 * carries no signature, with no receive-pack dispatch at all.  The refusal
 * is a requeue, not an error code. */
int test_dev_land_signed_third_party_before_push(void)
{
    int failures = 0;
    TEST("land: a third-party push between the intent and the push supersedes the stale pair without dispatching it") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], wt[1400], marker[1400], sibling[64];
        char queue[16384], log[65536];
        size_t queue_len = 0, log_len = 0;
        dlx_isolate("signed_third_party");
        ASSERT(dlx_signed_push_lossy(&rig, "signed_third_party", base, wt,
                                     marker, NULL));
        ASSERT(dlx_sibling(&rig, base, "refs/heads/main", sibling));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "queued");
        ASSERT_EQ(dlx_int(&c, "predecessor_seq"), 1);
        const char *log_path = dlx_str(&c, "log_path");
        ASSERT(log_path != NULL);
        ASSERT(dlx_slurp(log_path, log, sizeof(log) - 1, &log_len));
        log[log_len] = '\0';
        ASSERT(strstr(log, "stale signed intent") != NULL);
        dlx_end(&c);
        ASSERT(dlx_queue_bytes(queue, sizeof(queue), &queue_len));
        ASSERT(strstr(queue, "\"publication_signature\":\"\"") != NULL);
        ASSERT(!dlx_file_exists(marker));
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, sibling);
        ASSERT(dlx_is_ancestor(rig.bare, base, "refs/heads/main"));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}


/* CANONICAL_LIFECYCLE.md PUBLICATION: uncertain acknowledgements remain
 * first-class and the adapter observes the remote again before any further
 * mutation.  While the remote cannot be read, every step reports the
 * unavailable observation and dispatches nothing; once it answers, the
 * single retained update lands. */
int test_dev_land_signed_unknown_not_retried_blind(void)
{
    int failures = 0;
    TEST("land: an unknown push outcome is not re-sent while the remote cannot be observed") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], wt[1400], marker[1400], upload_pack[1400];
        dlx_isolate("signed_unknown_blind");
        ASSERT(dlx_signed_push_lossy(&rig, "signed_unknown_blind", base, wt,
                                     marker, NULL));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
        dlx_end(&c);
        ASSERT(dlx_marker_lines(marker, 1));
        (void)snprintf(upload_pack, sizeof(upload_pack), "%s.upload-pack",
                       rig.bare);
        ASSERT(dlx_write(upload_pack, "#!/bin/sh\nexit 75\n"));
        ASSERT(chmod(upload_pack, 0700) == 0);
        const char *blind[] = { "config", "remote.origin.uploadpack",
                                upload_pack, NULL };
        ASSERT(dlx_git(wt, blind) == 0);
        for (unsigned i = 0; i < 3; i++) {
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT_STR_EQ(dlx_err_code(&c), "REMOTE_OBSERVATION_UNAVAILABLE");
            dlx_end(&c);
            ASSERT(dlx_marker_lines(marker, 1));
        }
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        const char *see[] = { "config", "--unset", "remote.origin.uploadpack",
                              NULL };
        ASSERT(dlx_git(wt, see) == 0);
        ASSERT(dlx_dispatch_script(marker, "exec git-receive-pack \"$@\"\n"));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        ASSERT(dlx_marker_lines(marker, 2));
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

#endif /* !defined(_WIN32) */
