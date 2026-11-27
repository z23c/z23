/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "test/test_core.h"
#include "zmap/zmap.h"
#include <ctype.h>

static FILE *wf_in, *wf_out, *wf_err;
static size_t wf_small_sorts, wf_sorts;

static void wf_sort(void *base, size_t count, size_t width,
                    int (*cmp)(const void *, const void *))
{
    if (count < 2) {
        wf_small_sorts++;
        return;
    }
    wf_sorts++;
    qsort(base, count, width, cmp);
}

static int wf_main(int argc, char **argv);
#undef stdin
#undef stdout
#undef stderr
#define stdin wf_in
#define stdout wf_out
#define stderr wf_err
/* glibc's <stdio2.h> defines printf for compilers without __va_arg_pack. */
#undef printf
#define printf(...) fprintf(wf_out, __VA_ARGS__)
#define qsort wf_sort
#define main wf_main
#undef MAX_INPUT /* <limits.h> defines it; zmap main.c uses a private size */
#include "../../../contexts/commons/packages/zmap/app/main.c"
#undef main
#undef qsort
#undef printf
#undef stderr
#undef stdout
#undef stdin

#if defined(_WIN32)
#include "../../../contexts/commons/modules/vcs/src/vcs_walk.h"
static bool wf_observed_walk(const char *, vcs_walk_cb, void *);
static bool wf_observed_blob_hash(const char *, const char *, uint8_t[32]);
#define vcs_walk_tracked wf_observed_walk
#define vcs_blob_hash_file wf_observed_blob_hash
#define qsort wf_sort
#include "../../../contexts/commons/modules/vcs/src/vcs_walk.c"
#undef qsort
#undef vcs_blob_hash_file
#undef vcs_walk_tracked

static bool wf_walk_count(const char *path, uint32_t mode, uint64_t size,
                          int64_t modified, int64_t changed, void *opaque)
{
    (void)path;
    (void)mode;
    (void)size;
    (void)modified;
    (void)changed;
    size_t *count = opaque;
    (*count)++;
    return true;
}

static int wf_windows_empty_walk(void)
{
    int failures = 0;
    char root[PATH_MAX] = {0};
    size_t callbacks = 0;
    bool owned = test_mkdtemp(root, sizeof(root), "empty_vcs_walk") != NULL;
    (void)wf_observed_blob_hash;
    wf_small_sorts = wf_sorts = 0;
    ASSERT(owned);
    ASSERT(wf_observed_walk(root, wf_walk_count, &callbacks));
    ASSERT_EQ(callbacks, 0);
    ASSERT_EQ(wf_small_sorts, 0);
    ASSERT_EQ(wf_sorts, 0);
    PASS();
_test_next:;
    if (owned && test_rm_rf_recursive(root) != 0) failures++;
    return failures;
}
#endif

static FILE *wf_stream(char path[PATH_MAX])
{
    int fd = test_mkstemp(path, PATH_MAX, "wordfreq");
    if (fd < 0) return NULL;
    FILE *stream = fdopen(fd, "w+b");
    if (!stream) {
        (void)close(fd);
        (void)unlink(path);
    }
    return stream;
}

static bool wf_matches(FILE *stream, const char *expected)
{
    char text[256] = {0};
    if (fflush(stream) != 0 || fseek(stream, 0, SEEK_SET) != 0)
        return false;
    size_t n = fread(text, 1, sizeof(text) - 1, stream);
    return !ferror(stream) && feof(stream) &&
           n == strlen(expected) && strcmp(text, expected) == 0;
}

static int wf_case(const char *input, const char *output,
                   const char *diagnostic, size_t sorts)
{
    int failures = 0;
    char paths[3][PATH_MAX] = {{0}};
    wf_in = wf_out = wf_err = NULL;
    wf_small_sorts = wf_sorts = 0;
    wf_in = wf_stream(paths[0]);
    wf_out = wf_stream(paths[1]);
    wf_err = wf_stream(paths[2]);
    ASSERT(wf_in && wf_out && wf_err);
    size_t len = strlen(input);
    ASSERT_EQ(fwrite(input, 1, len, wf_in), len);
    ASSERT_EQ(fflush(wf_in), 0);
    ASSERT_EQ(fseek(wf_in, 0, SEEK_SET), 0);
    char *argv[] = {"wordfreq", "0", NULL};
    ASSERT_EQ(wf_main(2, argv), 0);
    ASSERT_EQ(wf_small_sorts, 0);
    ASSERT_EQ(wf_sorts, sorts);
    ASSERT(wf_matches(wf_out, output));
    ASSERT(wf_matches(wf_err, diagnostic));
    PASS();
_test_next:;
    FILE *streams[] = {wf_in, wf_out, wf_err};
    for (size_t i = 0; i < 3; i++) {
        if (streams[i] && fclose(streams[i]) != 0) failures++;
        if (paths[i][0] && unlink(paths[i]) != 0 && errno != ENOENT)
            failures++;
    }
    wf_in = wf_out = wf_err = NULL;
    return failures;
}

int test_wordfreq(void)
{
    int failures = 0;
    TEST("wordfreq production main guards empty and singleton sorts") {
        failures += wf_case("", "", "0 distinct words\n", 0);
        failures += wf_case("Pear pear", "      2 pear\n",
                            "1 distinct words\n", 0);
        failures += wf_case("pear pear banana apple",
                            "      2 pear\n      1 apple\n      1 banana\n",
                            "3 distinct words\n", 1);
    }
#if defined(_WIN32)
    failures += wf_windows_empty_walk();
#endif
    return failures;
}
