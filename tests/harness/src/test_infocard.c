/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove the infocard tool (build/bin/infocard, from tools/infocard.c).
 * The example spec renders at its declared size; a 50% bar puts gold pixels
 * in its fill and track pixels past it, while a background-only card has
 * neither; every way a spec can fail to fit (page height, width, wrapped
 * lines, fields, percent, canvas, line length, non-ASCII, read error) exits
 * non-zero with a message naming the problem and leaves no PNG behind. */

#include "test/test_core.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
int test_infocard(void)
{
    printf("\n=== infocard tests ===\n");
    printf("  skipped: the tool runs through fork/exec on POSIX hosts only\n");
    return 0;
}
#else

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define IC_BIN "build/bin/infocard"
#define IC_FIXTURE "tests/harness/fixtures/infocard_update.card"

/* Runs infocard SPEC OUT, capturing stdout+stderr; returns the exit code. */
static int ic_run(const char *spec, const char *out, char *log, size_t cap)
{
    int fds[2];
    if (pipe(fds) != 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        if (dup2(fds[1], STDOUT_FILENO) < 0 || dup2(fds[1], STDERR_FILENO) < 0)
            _exit(126);
        close(fds[0]);
        close(fds[1]);
        execl(IC_BIN, IC_BIN, spec, out, (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    size_t used = 0;
    ssize_t n;
    while (used + 1 < cap && (n = read(fds[0], log + used, cap - 1 - used)) > 0)
        used += (size_t)n;
    log[used] = '\0';
    char rest[256];
    while (read(fds[0], rest, sizeof(rest)) > 0) {}
    close(fds[0]);
    int status = 0;
    if (waitpid(pid, &status, 0) != pid)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static bool ic_write_bytes(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    bool ok = f && fwrite(data, 1, len, f) == len;
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok;
}

static bool ic_write(const char *path, const char *text)
{
    return ic_write_bytes(path, text, strlen(text));
}

static bool ic_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static uint32_t ic_be32(const uint8_t *b)
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

/* An RGB image decoded from a PNG with stored (uncompressed) deflate
 * blocks, the only form the native writer emits. */
struct ic_image {
    uint32_t w, h;
    uint8_t *rows; /* h rows of one filter byte (0) plus w RGB pixels */
};

static uint8_t *ic_read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf = NULL;
    long size = -1;
    if (f && fseek(f, 0, SEEK_END) == 0 && (size = ftell(f)) > 0 && fseek(f, 0, SEEK_SET) == 0)
        buf = malloc((size_t)size);
    if (buf && fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        buf = NULL;
    }
    if (f)
        fclose(f);
    *len = buf ? (size_t)size : 0;
    return buf;
}

/* Concatenates the IDAT chunk payloads of png (len bytes) into z. */
static size_t ic_png_idat(const uint8_t *png, size_t len, uint8_t *z)
{
    size_t used = 0;
    for (size_t at = 8; at + 12 <= len;) {
        uint32_t n = ic_be32(png + at);
        if (n > len - at - 12)
            return 0;
        if (memcmp(png + at + 4, "IDAT", 4) == 0) {
            memcpy(z + used, png + at + 8, n);
            used += n;
        }
        at += 12u + n;
    }
    return used;
}

/* Unpacks zlib-wrapped stored deflate blocks z (len bytes) into out. */
static size_t ic_unstore(const uint8_t *z, size_t len, uint8_t *out)
{
    size_t used = 0;
    for (size_t at = 2; at + 5 <= len;) {
        uint8_t head = z[at];
        size_t n = (size_t)z[at + 1] | ((size_t)z[at + 2] << 8);
        if ((head & 0x06u) != 0 || n > len - at - 5)
            return 0;
        memcpy(out + used, z + at + 5, n);
        used += n;
        at += 5u + n;
        if (head & 0x01u)
            return used;
    }
    return 0;
}

static bool ic_decode(const char *path, struct ic_image *img)
{
    static const uint8_t sig[8] = {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};
    size_t len = 0;
    uint8_t *png = ic_read_file(path, &len);
    bool ok = png && len > 33 && memcmp(png, sig, 8) == 0 && memcmp(png + 12, "IHDR", 4) == 0 &&
              png[24] == 8 && png[25] == 2;
    uint8_t *z = ok ? malloc(len) : NULL;
    img->rows = ok ? malloc(len) : NULL;
    if (ok && z && img->rows) {
        img->w = ic_be32(png + 16);
        img->h = ic_be32(png + 20);
        size_t zlen = ic_png_idat(png, len, z);
        ok = ic_unstore(z, zlen, img->rows) == (size_t)img->h * (1u + 3u * (size_t)img->w);
    } else {
        ok = false;
    }
    free(z);
    free(png);
    return ok;
}

static bool ic_pixel_is(const struct ic_image *img, uint32_t x, uint32_t y, uint8_t r, uint8_t g,
                        uint8_t b)
{
    const uint8_t *px = img->rows + (size_t)y * (1u + 3u * img->w) + 1u + 3u * x;
    return px[0] == r && px[1] == g && px[2] == b;
}

static size_t ic_count(const struct ic_image *img, uint8_t r, uint8_t g, uint8_t b)
{
    size_t n = 0;
    for (uint32_t y = 0; y < img->h; y++)
        for (uint32_t x = 0; x < img->w; x++)
            n += ic_pixel_is(img, x, y, r, g, b) ? 1u : 0u;
    return n;
}

/* Renders spec_text into dir/NAME.png and decodes it. */
static bool ic_render_text(const char *dir, const char *name, const char *spec_text,
                           struct ic_image *img)
{
    char spec[PATH_MAX], out[PATH_MAX], log[2048];
    snprintf(spec, sizeof(spec), "%s/%s.card", dir, name);
    snprintf(out, sizeof(out), "%s/%s.png", dir, name);
    return ic_write(spec, spec_text) && ic_run(spec, out, log, sizeof(log)) == 0 &&
           ic_decode(out, img);
}

/* Runs spec bytes that must fail: exit 1, needle in the log, no PNG. */
static bool ic_fails_with_bytes(const char *dir, const char *data, size_t len,
                                const char *needle)
{
    char spec[PATH_MAX], out[PATH_MAX], log[2048];
    snprintf(spec, sizeof(spec), "%s/bad.card", dir);
    snprintf(out, sizeof(out), "%s/bad.png", dir);
    (void)unlink(out);
    if (!ic_write_bytes(spec, data, len))
        return false;
    int rc = ic_run(spec, out, log, sizeof(log));
    if (rc != 1 || !strstr(log, needle))
        printf("(rc=%d log: %s) ", rc, log);
    return rc == 1 && strstr(log, needle) != NULL && !ic_exists(out);
}

static bool ic_fails_with(const char *dir, const char *spec_text, const char *needle)
{
    return ic_fails_with_bytes(dir, spec_text, strlen(spec_text), needle);
}

static int ic_case_render(const char *dir)
{
    int failures = 0;
    struct ic_image img = {0};
    TEST_CASE("the example spec renders at its declared size with gold title pixels") {
        char out[PATH_MAX], log[2048];
        snprintf(out, sizeof(out), "%s/update.png", dir);
        ASSERT_EQ(ic_run(IC_FIXTURE, out, log, sizeof(log)), 0);
        ASSERT(ic_decode(out, &img));
        ASSERT_EQ(img.w, 1080u);
        ASSERT_EQ(img.h, 1620u);
        ASSERT(ic_count(&img, 242, 181, 68) > 1000u);
    } TEST_END
    free(img.rows);
    return failures;
}

static int ic_case_pixels(const char *dir)
{
    int failures = 0;
    struct ic_image bar = {0}, blank = {0};
    TEST_CASE("a 50% bar fills half its track; a background-only card has neither colour") {
        /* 600 px page, 72 px margins: the track spans x 72..527 at y 100..117
         * and a 50% fill ends at x 300. */
        ASSERT(ic_render_text(dir, "bar", "canvas 600 400\nbar Half | 50\n", &bar));
        ASSERT(ic_pixel_is(&bar, 186, 108, 242, 181, 68));
        ASSERT(ic_pixel_is(&bar, 498, 108, 36, 56, 68));
        ASSERT(ic_render_text(dir, "blank", "canvas 600 400\n", &blank));
        ASSERT_EQ(ic_count(&blank, 242, 181, 68), 0u);
        ASSERT_EQ(ic_count(&blank, 36, 56, 68), 0u);
    } TEST_END
    free(bar.rows);
    free(blank.rows);
    return failures;
}

struct ic_bad_case {
    const char *name;
    const char *spec;
    const char *needle;
};

static const struct ic_bad_case IC_BAD[] = {
    {"content too tall for the canvas fails",
     "canvas 400 400\ntitle T | K | D\nsection A\ncheck one\ncheck two\ncheck three\n"
     "check four\ncheck five\ncheck six\ncheck seven\n",
     "line 6: content needs"},
    {"a footer without room names the footer line",
     "canvas 320 320\ncheck one\ncheck two\ncheck three\ncheck four\nfooter end\n",
     "line 6: content needs"},
    {"a second footer fails", "canvas 600 600\nfooter a\nfooter b\n",
     "line 3: only one footer is allowed (the first is on line 2)"},
    {"canvas numbers too large for unsigned fail as out of range",
     "canvas 99999999999999999999 600\n", "out of range"},
    {"an unknown directive names its line", "# note\ncanvas 600 600\nsection A\nbogus x | y\n",
     "line 4: unknown directive 'bogus'"},
    {"a canvas below the minimum fails", "canvas 100 100\nsection A\n", "out of range"},
    {"a canvas above the maximum fails", "canvas 99999 600\nsection A\n", "out of range"},
    {"a malformed canvas line fails", "canvas wide tall\n", "canvas takes a width and a height"},
    {"canvas after another directive fails", "section A\ncanvas 600 600\n",
     "line 2: canvas must be the first directive"},
    {"a non-numeric percent fails", "canvas 600 600\nbar A | abc\n", "bar percent 'abc'"},
    {"a percent above 100 fails", "canvas 600 600\nbar A | 150\n", "bar percent '150'"},
    {"a percent with trailing text fails", "canvas 600 600\nbar A | 50x\n", "bar percent '50x'"},
    {"an extra field fails", "canvas 600 600\nstat 1 | a | b\n", "'stat' takes at most 2 fields"},
    {"four stats on a narrow canvas fail", "canvas 320 600\nstat 1 | a\nstat 2 | b\nstat 3 | c\nstat 4 | d\n",
     "line 2: the canvas is too narrow for 4 stats"},
    {"a cta on a narrow canvas fails", "canvas 320 900\ncta Help | @bot | ask\n",
     "cta heading 'Help' does not fit"},
    {"a title wider than the page fails", "canvas 320 600\ntitle ABCDEFGHIJ\n",
     "title 'ABCDEFGHIJ' does not fit"},
    {"a word wider than its line fails", "canvas 320 600\ncheck Supercalifragilisticexpialidocious\n",
     "check 'Supercalifragilisticexpialidocious' does not fit"},
    {"a seventh wrapped line fails",
     "canvas 320 2000\nsubtitle word word word word word word word word word word word word "
     "word word word word word word word word\n",
     "subtitle needs more than 6 lines"},
    {"a bar label that collides with its note fails",
     "canvas 400 600\nbar A long label that runs into the note | 40 | forty percent\n",
     "bar label 'A long label that runs into the note' does not fit"},
    {"non-ASCII text fails", "canvas 600 600\ncheck caf\xc3\xa9\n", "line 2: only printable ASCII"},
};

static int ic_case_bad(const char *dir)
{
    int failures = 0;
    for (size_t i = 0; i < sizeof(IC_BAD) / sizeof(IC_BAD[0]); i++) {
        TEST_CASE(IC_BAD[i].name) {
            ASSERT(ic_fails_with(dir, IC_BAD[i].spec, IC_BAD[i].needle));
        } TEST_END
    }
    return failures;
}

static int ic_case_long_line(const char *dir)
{
    int failures = 0;
    char spec[700];
    memcpy(spec, "canvas 600 600\ncheck ", 21);
    memset(spec + 21, 'a', 600);
    memcpy(spec + 621, "\n", 2);
    TEST_CASE("a line longer than 510 characters fails instead of splitting") {
        ASSERT(ic_fails_with(dir, spec, "line 2: the line is longer than 510 characters"));
    } TEST_END
    return failures;
}

/* The last line has no newline, so the reader hits end of file right after
 * the NUL: the bytes after it must still be checked. */
static int ic_case_nul(const char *dir)
{
    int failures = 0;
    static const char spec[] = "canvas 600 600\ncheck ab\0\x01x";
    TEST_CASE("an embedded NUL in the last line fails instead of hiding bytes") {
        ASSERT(ic_fails_with_bytes(dir, spec, sizeof(spec) - 1u, "line 2: only printable ASCII"));
    } TEST_END
    return failures;
}

static int ic_case_missing(const char *dir)
{
    int failures = 0;
    char log[2048], out[PATH_MAX];
    snprintf(out, sizeof(out), "%s/none.png", dir);
    TEST_CASE("a missing spec file fails with the usage exit code") {
        ASSERT_EQ(ic_run("tests/harness/fixtures/infocard_absent.card", out, log, sizeof(log)), 2);
        ASSERT(!ic_exists(out));
    } TEST_END
    return failures;
}

/* The temp directory itself is the spec: fopen succeeds, reading fails. */
static int ic_case_unreadable(const char *dir)
{
    int failures = 0;
    char log[2048], out[PATH_MAX];
    snprintf(out, sizeof(out), "%s/none.png", dir);
    TEST_CASE("a spec that cannot be read fails instead of rendering a partial card") {
        ASSERT_EQ(ic_run(dir, out, log, sizeof(log)), 1);
        ASSERT(strstr(log, "cannot read the spec") != NULL);
        ASSERT(!ic_exists(out));
    } TEST_END
    return failures;
}

int test_infocard(void)
{
    int failures = 0;
    char dir[PATH_MAX];
    printf("\n=== infocard tests ===\n");
    if (!test_mkdtemp(dir, sizeof(dir), "infocard"))
        return 1;
    failures += ic_case_render(dir);
    failures += ic_case_pixels(dir);
    failures += ic_case_bad(dir);
    failures += ic_case_long_line(dir);
    failures += ic_case_nul(dir);
    failures += ic_case_missing(dir);
    failures += ic_case_unreadable(dir);
    (void)test_rm_rf_recursive(dir);
    return failures;
}

#endif
