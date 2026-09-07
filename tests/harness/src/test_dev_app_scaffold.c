/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.app.scaffold — the materializer behind `z23 dev app scaffold <app>
 * <resource>`. These cases exist because a scaffold that is trusted with a
 * developer's checkout has to be provably fail-closed:
 *
 *   1. what it writes IS what dev.app.plan previewed — same paths, and the
 *      bytes on disk equal the bytes the shared slice builder produced;
 *   2. a target that already exists with DIFFERENT content stops the whole
 *      command before any byte is written, and leaves no temp file behind;
 *   3. running it twice is a no-op: 0 written, N unchanged;
 *   4. an inadmissible app_id or resource name never reaches the disk.
 *
 * Each case runs against a fresh mkdtemp() scratch checkout carrying only
 * the App manifest and the registry the slice touches, so the test never
 * writes into the real tree.
 */

#include "test/test_core.h"

#include "devloop.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DAS_CHECK(name, expr) do {                            \
    printf("dev_app_scaffold: %s... ", (name));               \
    if ((expr)) { printf("OK\n"); }                           \
    else { printf("FAIL\n"); failures++; }                    \
} while (0)

/* Copy one file from the real checkout into the scratch checkout. */
static bool das_copy(const char *from, const char *to)
{
    FILE *in = fopen(from, "rb");
    if (!in)
        return false;
    FILE *out = fopen(to, "wb");
    if (!out) {
        (void)fclose(in);
        return false;
    }
    char chunk[4096];
    size_t n;
    bool ok = true;
    while ((n = fread(chunk, 1, sizeof(chunk), in)) > 0) {
        if (fwrite(chunk, 1, n, out) != n) {
            ok = false;
            break;
        }
    }
    ok = ok && ferror(in) == 0;
    (void)fclose(in);
    return fclose(out) == 0 && ok;
}

/* A scratch checkout with exactly what the social/posts slice reads and
 * writes: the App manifest and the test-group catalog. */
static bool das_make_root(char *root, size_t cap)
{
    const char *tmp = getenv("TMPDIR");
    (void)snprintf(root, cap, "%s/zcl_das_XXXXXX",
                   (tmp && tmp[0]) ? tmp : "/tmp");
    if (!mkdtemp(root))
        return false;
    char path[512];
    (void)snprintf(path, sizeof(path), "%s/contexts", root);
    if (mkdir(path, 0755) != 0)
        return false;
    (void)snprintf(path, sizeof(path), "%s/contexts/commons", root);
    if (mkdir(path, 0755) != 0)
        return false;
    (void)snprintf(path, sizeof(path), "%s/contexts/commons/apps", root);
    if (mkdir(path, 0755) != 0)
        return false;
    (void)snprintf(path, sizeof(path), "%s/contexts/commons/apps/social", root);
    if (mkdir(path, 0755) != 0)
        return false;
    (void)snprintf(path, sizeof(path),
                   "%s/contexts/commons/apps/social/app.def", root);
    if (!das_copy("contexts/commons/apps/social/app.def", path))
        return false;
    (void)snprintf(path, sizeof(path), "%s/tools", root);
    if (mkdir(path, 0755) != 0)
        return false;
    (void)snprintf(path, sizeof(path), "%s/tools/dev", root);
    if (mkdir(path, 0755) != 0)
        return false;
    (void)snprintf(path, sizeof(path), "%s/tools/dev/test_group_catalog.def",
                   root);
    FILE *fp = fopen(path, "wb");
    if (!fp)
        return false;
    (void)fputs("ZCL_TEST_GROUP(hex_codec)\n", fp);
    return fclose(fp) == 0;
}

/* Bytes of one file inside the scratch checkout, or NULL. */
static char *das_slurp(const char *root, const char *rel, size_t *len_out)
{
    char path[768];
    (void)snprintf(path, sizeof(path), "%s/%s", root, rel);
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return NULL;
    char *buf = malloc(65536);
    if (!buf) {
        (void)fclose(fp);
        return NULL;
    }
    size_t n = fread(buf, 1, 65535, fp);
    (void)fclose(fp);
    buf[n] = 0;
    *len_out = n;
    return buf;
}

/* True when any name under dir (one level) ends in the scaffold temp
 * suffix — a refusal or a crash must never leave one behind. */
static bool das_temp_left(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return false;
    bool found = false;
    const struct dirent *e;
    while (!found && (e = readdir(d)) != NULL)
        found = strstr(e->d_name, ".z23scaffold.tmp") != NULL;
    (void)closedir(d);
    return found;
}

/* Case 1 + 3: the scaffold writes the planned slice, and re-running is a
 * byte-for-byte no-op. */
static int das_writes_the_plan(void)
{
    int failures = 0;
    char root[128];
    if (!das_make_root(root, sizeof(root))) {
        printf("dev_app_scaffold: scratch checkout... FAIL\n");
        return 1;
    }
    char body[8192];
    size_t n = zcl_devloop_app_scaffold_json(root, "social", "posts", body,
                                             sizeof(body));
    DAS_CHECK("first run materializes the slice",
              n > 0 && strstr(body, "\"status\":\"materialized\"") &&
              strstr(body, "\"written\":6,\"unchanged\":0"));

    struct zcl_devloop_app_slice *slice =
        zcl_devloop_app_slice_build(root, "social", "posts");
    DAS_CHECK("plan and scaffold agree on the slice", slice != NULL);
    bool bytes_match = slice != NULL;
    for (size_t i = 0; slice && i < slice->file_count; i++) {
        if (slice->files[i].kind != ZCL_DEVLOOP_APP_SLICE_CREATE)
            continue;
        size_t have_len = 0;
        char *have = das_slurp(root, slice->files[i].path, &have_len);
        bytes_match = bytes_match && have &&
                      have_len == slice->files[i].body_len &&
                      memcmp(have, slice->files[i].body,
                             slice->files[i].body_len) == 0;
        free(have);
    }
    DAS_CHECK("every written file is byte-equal to the planned file",
              bytes_match);

    size_t cat_len = 0;
    char *cat = das_slurp(root, "tools/dev/test_group_catalog.def", &cat_len);
    DAS_CHECK("the test group row is registered",
              cat && strstr(cat, "ZCL_TEST_GROUP(social_posts_slice)\n") &&
              strstr(cat, "ZCL_TEST_GROUP(hex_codec)\n"));
    free(cat);

    n = zcl_devloop_app_scaffold_json(root, "social", "posts", body,
                                      sizeof(body));
    DAS_CHECK("a second run reports 0 written, 6 unchanged",
              n > 0 && strstr(body, "\"written\":0,\"unchanged\":6"));

    size_t again_len = 0;
    char *again = das_slurp(root, "tools/dev/test_group_catalog.def",
                            &again_len);
    DAS_CHECK("the registry row is not doubled",
              again && again_len == cat_len);
    free(again);
    zcl_devloop_app_slice_free(slice);
    return failures;
}

/* Case 2: one differing target refuses the whole slice. */
static int das_refuses_a_conflict(void)
{
    int failures = 0;
    char root[128];
    if (!das_make_root(root, sizeof(root))) {
        printf("dev_app_scaffold: scratch checkout... FAIL\n");
        return 1;
    }
    char path[768];
    (void)snprintf(path, sizeof(path), "%s/engine", root);
    (void)mkdir(path, 0755);
    (void)snprintf(path, sizeof(path), "%s/engine/models", root);
    (void)mkdir(path, 0755);
    (void)snprintf(path, sizeof(path), "%s/engine/models/src", root);
    (void)mkdir(path, 0755);
    (void)snprintf(path, sizeof(path), "%s/engine/models/src/posts.c", root);
    FILE *fp = fopen(path, "wb");
    bool planted = fp && fputs("/* mine, not yours */\n", fp) >= 0 &&
                   fclose(fp) == 0;

    char body[8192];
    size_t n = zcl_devloop_app_scaffold_json(root, "social", "posts", body,
                                             sizeof(body));
    DAS_CHECK("a differing target refuses the whole slice",
              planted && n > 0 && strstr(body, "\"status\":\"refused\"") &&
              strstr(body, "refused: engine/models/src/posts.c exists with "
                           "different content"));
    DAS_CHECK("the refusal wrote nothing", strstr(body, "\"written\":0"));

    size_t len = 0;
    char *have = das_slurp(root, "engine/models/src/posts.c", &len);
    DAS_CHECK("the conflicting file is untouched",
              have && strcmp(have, "/* mine, not yours */\n") == 0);
    free(have);

    have = das_slurp(root, "engine/models/include/models/posts.h", &len);
    DAS_CHECK("no sibling file was written", have == NULL);
    free(have);

    size_t cat_len = 0;
    char *cat = das_slurp(root, "tools/dev/test_group_catalog.def", &cat_len);
    DAS_CHECK("the registry row was not appended",
              cat && strstr(cat, "social_posts_slice") == NULL);
    free(cat);

    (void)snprintf(path, sizeof(path), "%s/engine/models/src", root);
    DAS_CHECK("no temp file was left behind", !das_temp_left(path));
    return failures;
}

/* Case 4: input bounds. An inadmissible name never reaches the disk. */
static int das_refuses_bad_input(void)
{
    int failures = 0;
    char root[128];
    if (!das_make_root(root, sizeof(root))) {
        printf("dev_app_scaffold: scratch checkout... FAIL\n");
        return 1;
    }
    char body[8192];
    static const char *const bad_resources[] = {
        "", "Posts", "1posts", "posts_", "po__sts", "posts-a", "../etc"
    };
    bool all_refused = true;
    for (size_t i = 0; i < sizeof(bad_resources) / sizeof(bad_resources[0]);
         i++) {
        all_refused = all_refused &&
                      !zcl_devloop_app_resource_valid(bad_resources[i]) &&
                      zcl_devloop_app_scaffold_json(root, "social",
                                                    bad_resources[i], body,
                                                    sizeof(body)) == 0;
    }
    DAS_CHECK("an inadmissible resource name is refused", all_refused);
    DAS_CHECK("a conventional resource name is admitted",
              zcl_devloop_app_resource_valid("posts") &&
              zcl_devloop_app_resource_valid("blog_post"));
    DAS_CHECK("an unknown App is refused",
              zcl_devloop_app_scaffold_json(root, "nosuchapp", "posts", body,
                                            sizeof(body)) == 0);
    DAS_CHECK("an unresolvable checkout root is refused",
              zcl_devloop_app_scaffold_json("/nonexistent/z23/root", "social",
                                            "posts", body,
                                            sizeof(body)) == 0);
    size_t len = 0;
    char *have = das_slurp(root, "engine/models/src/posts.c", &len);
    DAS_CHECK("nothing was written for any refused input", have == NULL);
    free(have);
    return failures;
}

int test_dev_app_scaffold(void)
{
    int failures = 0;
    failures += das_writes_the_plan();
    failures += das_refuses_a_conflict();
    failures += das_refuses_bad_input();
    return failures;
}
