/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_dev_intake: dev.land.intake (tools/command/native_dev_intake.c) on a lab of
 * lane clones and signed READY posts saved to a posts_file. A good post is
 * ACCEPT_FOR_QUEUE, a post with a broken signature, a foreign author or a
 * core/ path is REFUSE, two posts adding the same file differently give the
 * later one CONFLICT(with=<the earlier id>), and a run without commit (or
 * with commit but no confirm) leaves the checkout's refs untouched and
 * reports applied=false. */

#include "test/test_dev_batch_fixture.h"

#include "base/hex.h"
#include "platform/time_compat.h"
#include "crypto/ed25519.h"
#include "session/fleet_board_proto.h"
#include "command/native_dev_land_remote_shared.h"

struct di {
    struct dbf f;
    char bdir[800], allow[900], posts[900];
    uint8_t seed[32], pk[32];
    char pkhex[65];
    char ids[12][65];
};

static bool di_bundle(struct di *d, const char *lane, const char *file,
                      const char *text, char sha[65])
{
    char path[900], tmp[1000], dst[1000];
    const char *mk[] = {"bundle", "create", tmp, "HEAD", "^origin/main", NULL};
    char hex[SHA256_OUTPUT_SIZE * 2 + 1];
    char head[41];
    if (!dbf_lane(&d->f, lane, NULL, path, head) ||
        !dbf_commit_file(path, file, text))
        return false;
    (void)snprintf(tmp, sizeof(tmp), "%s/%s.tmp", d->bdir, lane);
    if (!dbf_git(path, mk) || !zcl_dlr_file_sha256(tmp, hex))
        return false;
    (void)snprintf(dst, sizeof(dst), "%s/%s.bundle", d->bdir, hex);
    (void)snprintf(sha, 65, "%s", hex);
    return rename(tmp, dst) == 0;
}

/* One signed READY post as a board-list row; flip=true breaks the text after
 * signing. Returns the id in ids[slot]. */
static void di_post_r(struct di *d, struct json_value *arr, int slot,
                      uint64_t at, const char *text_in, const char *receipt,
                      bool omit_receipt, bool flip)
{
    struct fleet_board_post p;
    struct json_value r;
    char text[256], hex[129];
    memset(&p, 0, sizeof(p));
    p.kind = FLEET_BOARD_KIND_NOTE;
    p.scope = FLEET_BOARD_SCOPE_PUBLIC;
    p.created_at = at;
    p.ttl = 86400;
    (void)snprintf(p.room, sizeof(p.room), "fleet");
    (void)snprintf(p.agent, sizeof(p.agent), "lab");
    (void)snprintf(text, sizeof(text), "%s", text_in);
    (void)snprintf(p.receipt, sizeof(p.receipt), "%s", receipt);
    p.text_len = (uint32_t)strlen(text);
    memcpy(p.text, text, p.text_len + 1);
    (void)fleet_board_post_sign(&p, d->seed, d->pk);
    zcl_hex_encode(p.id, 32, d->ids[slot]);
    if (flip)
        text[strlen(text) - 1] = 'X';
    json_init(&r);
    json_set_object(&r);
    (void)json_push_kv_str(&r, "id", d->ids[slot]);
    (void)json_push_kv_str(&r, "kind", "note");
    (void)json_push_kv_int(&r, "created_at", (int64_t)at);
    (void)json_push_kv_int(&r, "ttl", 86400);
    zcl_hex_encode(p.ref, 32, hex);
    (void)json_push_kv_str(&r, "ref", hex);
    zcl_hex_encode(d->pk, 32, hex);
    (void)json_push_kv_str(&r, "host", hex);
    zcl_hex_encode(p.signature, 64, hex);
    (void)json_push_kv_str(&r, "signature", hex);
    (void)json_push_kv_str(&r, "agent", "lab");
    (void)json_push_kv_str(&r, "scope", "public");
    (void)json_push_kv_str(&r, "room", "fleet");
    if (!omit_receipt && receipt[0])
        (void)json_push_kv_str(&r, "receipt", receipt);
    (void)json_push_kv_str(&r, "text", text);
    (void)json_push_back(arr, &r);
    json_free(&r);
}

static void di_post(struct di *d, struct json_value *arr, int slot,
                    uint64_t at, const char *sha, bool flip)
{
    char text[128];
    (void)snprintf(text, sizeof(text), "READY sha256=%s size=1 fixture", sha);
    di_post_r(d, arr, slot, at, text, "", false, flip);
}

static bool di_write_posts(struct di *d, const struct json_value *arr)
{
    static char buf[32768];
    struct json_value doc;
    bool ok;
    json_init(&doc);
    json_set_object(&doc);
    (void)json_push_kv(&doc, "posts", arr);
    ok = json_write(&doc, buf, sizeof(buf)) < sizeof(buf) && dbf_put(d->posts, buf);
    json_free(&doc);
    return ok;
}

static void di_run(struct di *d, bool commit, struct zcl_command_reply *reply,
                   char *dump, size_t cap)
{
    const char *pairs[] = {"posts_file", d->posts, "repo", d->f.mainco,
                           "bundle_dir", d->bdir, "allow", d->allow, NULL};
    const char *flags[] = {"commit", NULL};
    dbf_call(zcl_native_handle_dev_intake, &d->f, pairs, commit ? flags : NULL,
             reply, dump, cap);
}

static bool di_refs(const struct di *d, char *out, size_t cap)
{
    const char *argv[] = {"git", "-C", d->f.mainco, "for-each-ref", NULL};
    return zcl_spawn_capture(argv, out, cap, 30000) == 0;
}

static bool di_setup(struct di *d)
{
    char p[900];
    memset(d, 0, sizeof(*d));
    if (!dbf_setup(&d->f, "intake"))
        return false;
    (void)snprintf(d->bdir, sizeof(d->bdir), "%s/bundles", d->f.root);
    (void)snprintf(d->allow, sizeof(d->allow), "%s/allow.txt", d->f.root);
    (void)snprintf(d->posts, sizeof(d->posts), "%s/posts.json", d->f.root);
    if (!dbf_mkdirs(d->bdir))
        return false;
    memset(d->seed, 7, 32);
    {
        uint8_t sk[32];
        ed25519_keypair(d->pk, sk, d->seed);
        memcpy(d->seed, sk, 32);
    }
    zcl_hex_encode(d->pk, 32, d->pkhex);
    (void)snprintf(p, sizeof(p), "# allowed\n%s\n", d->pkhex);
    return dbf_put(d->allow, p);
}

int test_dev_intake(void);
int test_dev_intake(void)
{
    int failures = 0;
    struct di d;
    struct zcl_command_reply reply;
    struct json_value arr;
    char dump[16384], shaA[65], shaB[65], shaC[65], shaD[65], shaE[65];
    char before[4096], after[4096];

    ASSERT(di_setup(&d));
    ASSERT(di_bundle(&d, "good", "src/ok.c", "int ok;\n", shaA));
    ASSERT(di_bundle(&d, "core", "core/x.c", "int x;\n", shaB));
    ASSERT(di_bundle(&d, "same1", "src/same.c", "int a;\n", shaC));
    ASSERT(di_bundle(&d, "same2", "src/same.c", "int b;\n", shaD));
    ASSERT(di_bundle(&d, "bad", "src/bad.c", "int z;\n", shaE));
    ASSERT(di_refs(&d, before, sizeof(before)));

    TEST("intake: the leaf is registered") {
        ASSERT(zcl_command_registry_find(zcl_command_catalog(), "dev.land.intake",
                                         NULL) != NULL);
        PASS();
    }

    TEST("intake: a good post is ACCEPT_FOR_QUEUE") {
        json_init(&arr);
        json_set_array(&arr);
        di_post(&d, &arr, 0, (uint64_t)platform_time_wall_unix() + 0, shaA, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"verdict\":\"ACCEPT_FOR_QUEUE\"") != NULL);
        ASSERT(strstr(dump, "\"applied\":false") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: a bad signature and a core/ path are REFUSE") {
        json_init(&arr);
        json_set_array(&arr);
        di_post(&d, &arr, 1, (uint64_t)platform_time_wall_unix() + 1, shaE, true);
        di_post(&d, &arr, 2, (uint64_t)platform_time_wall_unix() + 2, shaB, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(bad_signature)") != NULL);
        ASSERT(strstr(dump, "REFUSE(denied_path)") != NULL);
        ASSERT(strstr(dump, "ACCEPT_FOR_QUEUE") == NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: an author outside the allow file is REFUSE") {
        json_init(&arr);
        json_set_array(&arr);
        di_post(&d, &arr, 3, (uint64_t)platform_time_wall_unix() + 3, shaA, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        ASSERT(dbf_put(d.allow, "# nobody\n11111111111111111111111111111111"
                                "11111111111111111111111111111111\n"));
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(author_not_allowed)") != NULL);
        zcl_command_reply_free(&reply);
        (void)snprintf(dump, sizeof(dump), "%s\n", d.pkhex);
        ASSERT(dbf_put(d.allow, dump));
        PASS();
    }

    TEST("intake: two posts adding the same file differently CONFLICT") {
        char want[96];
        json_init(&arr);
        json_set_array(&arr);
        di_post(&d, &arr, 4, (uint64_t)platform_time_wall_unix() + 4, shaC, false);
        di_post(&d, &arr, 5, (uint64_t)platform_time_wall_unix() + 5, shaD, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        (void)snprintf(want, sizeof(want), "CONFLICT(with=%.12s)", d.ids[4]);
        ASSERT(strstr(dump, "\"verdict\":\"ACCEPT_FOR_QUEUE\"") != NULL);
        ASSERT(strstr(dump, want) != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: the live READY form (lane path, commit, text) is ACCEPT_FOR_QUEUE") {
        char lane[900], head[41], text[512];
        ASSERT(dbf_lane(&d.f, "live", NULL, lane, head));
        ASSERT(dbf_commit_file(lane, "src/live.c", "int live;\n"));
        ASSERT(dbf_rev(lane, "HEAD", head));
        (void)snprintf(text, sizeof(text),
                       "READY %s %s Reject future timestamps; fresh base, lint pass.",
                       lane, head);
        json_init(&arr);
        json_set_array(&arr);
        di_post_r(&d, &arr, 6, (uint64_t)platform_time_wall_unix() + 6, text, "", false, false);
        (void)snprintf(text, sizeof(text),
                       "READY /nonexistent/other-host/lane %s remote lane", head);
        di_post_r(&d, &arr, 7, (uint64_t)platform_time_wall_unix() + 7, text, "", false, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"verdict\":\"ACCEPT_FOR_QUEUE\"") != NULL);
        ASSERT(strstr(dump, head) != NULL);
        ASSERT(strstr(dump, "REFUSE(invalid_lane)") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: traversal and repository subdirectories are refused") {
        char lane[900], head[41], text[1200];
        ASSERT(dbf_lane(&d.f, "hostile", NULL, lane, head));
        json_init(&arr);
        json_set_array(&arr);
        (void)snprintf(text, sizeof(text), "READY %s/../hostile %s traversal", lane, head);
        di_post_r(&d, &arr, 10, (uint64_t)platform_time_wall_unix(), text, "", false, false);
        (void)snprintf(text, sizeof(text), "READY %s/.. %s parent", lane, head);
        di_post_r(&d, &arr, 11, (uint64_t)platform_time_wall_unix(), text, "", false, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(invalid_lane)") != NULL);
        ASSERT(strstr(dump, "ACCEPT_FOR_QUEUE") == NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: rename into core is refused") {
        char lane[900], head[41], text[1200], sha[65], tmp[1000], dst[1000];
        const char *mv[] = {"mv", "a.c", "core/a.c", NULL};
        const char *commit[] = {"commit", "-q", "-m", "rename", NULL};
        const char *bundle[] = {"bundle", "create", tmp, "HEAD", "^origin/main", NULL};
        char dir[1000];
        ASSERT(dbf_lane(&d.f, "rename", NULL, lane, head));
        (void)snprintf(dir, sizeof(dir), "%s/core", lane);
        ASSERT(dbf_mkdirs(dir));
        ASSERT(dbf_git(lane, mv));
        ASSERT(dbf_git(lane, commit));
        (void)snprintf(tmp, sizeof(tmp), "%s/rename.tmp", d.bdir);
        ASSERT(dbf_git(lane, bundle));
        ASSERT(zcl_dlr_file_sha256(tmp, sha));
        (void)snprintf(dst, sizeof(dst), "%s/%s.bundle", d.bdir, sha);
        ASSERT(rename(tmp, dst) == 0);
        (void)snprintf(text, sizeof(text), "READY sha256=%s size=1 rename", sha);
        json_init(&arr);
        json_set_array(&arr);
        di_post_r(&d, &arr, 10, (uint64_t)platform_time_wall_unix(), text, "", false, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(denied_path)") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: expired signed post is refused") {
        json_init(&arr);
        json_set_array(&arr);
        di_post(&d, &arr, 10, 1000, shaA, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(post_expired_or_invalid_time)") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: a post with a receipt verifies; a row missing it is bad_signature") {
        json_init(&arr);
        json_set_array(&arr);
        di_post_r(&d, &arr, 8, (uint64_t)platform_time_wall_unix() + 8, "READY sha256=0000000000000000000000000000000000000000000000000000000000000000 size=1 r",
                  "unit=intake gate=ok", false, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(bad_signature)") == NULL);
        ASSERT(strstr(dump, "REFUSE(no_bundle)") != NULL || strstr(dump, "REFUSE(fetch_failed)") != NULL);
        zcl_command_reply_free(&reply);
        json_init(&arr);
        json_set_array(&arr);
        di_post_r(&d, &arr, 9, (uint64_t)platform_time_wall_unix() + 9, "READY sha256=0000000000000000000000000000000000000000000000000000000000000000 size=1 r",
                  "unit=intake gate=ok", true, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(bad_signature)") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: without commit (or without confirm) nothing is changed") {
        di_run(&d, false, &reply, dump, sizeof(dump));
        zcl_command_reply_free(&reply);
        di_run(&d, true, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"commit\":true") != NULL);
        ASSERT(strstr(dump, "\"applied\":false") != NULL);
        ASSERT(strstr(dump, "\"queued\"") == NULL);
        zcl_command_reply_free(&reply);
        ASSERT(di_refs(&d, after, sizeof(after)));
        ASSERT(strcmp(before, after) == 0);
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(d.f.root);
    if (failures == 0)
        printf("test_dev_intake: all passed\n");
    else
        printf("test_dev_intake: %d FAILED\n", failures);
    return failures;
}
