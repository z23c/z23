/* ztemplate tests: parsing, rendering, lookup failures, overflow
 * size reporting, comments, whitespace trimming, var enumeration,
 * and a randomized differential test against a reference renderer. */
#include "ztemplate/ztemplate.h"

#include <stdint.h>
#include <stdckdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
    ((void)0)

/* Simple map lookup over (name, value) pairs. */
struct kv { const char *k; const char *v; };

static bool kv_lookup(const char *name, size_t name_len,
                      const char **value, size_t *value_len, void *ctx)
{
    const struct kv *kvs = ctx;
    for (size_t i = 0; kvs[i].k; i++) {
        if (strlen(kvs[i].k) == name_len &&
            memcmp(kvs[i].k, name, name_len) == 0) {
            *value = kvs[i].v;
            *value_len = strlen(kvs[i].v);
            return true;
        }
    }
    return false;
}

static void test_basic_render(void)
{
    const char *t = "Hello {{name}}, you have {{count}} messages.";
    ztemplate *tp = ztemplate_parse(t, strlen(t), NULL);
    CHECK(tp != NULL);
    struct kv kvs[] = { { "name", "Ada" }, { "count", "3" }, { 0, 0 } };
    char out[128];
    size_t n = 0;
    CHECK(ztemplate_render(tp, kv_lookup, kvs, out, sizeof out, &n)
          == ZTEMPLATE_OK);
    CHECK(strcmp(out, "Hello Ada, you have 3 messages.") == 0);
    CHECK(n == strlen(out));
    ztemplate_free(tp);
}

static void test_whitespace_and_reuse(void)
{
    const char *t = "{{  x  }}+{{x}}={{x}}";
    ztemplate *tp = ztemplate_parse(t, strlen(t), NULL);
    CHECK(tp != NULL);
    struct kv kvs[] = { { "x", "1" }, { 0, 0 } };
    char out[32];
    size_t n = 0;
    CHECK(ztemplate_render(tp, kv_lookup, kvs, out, sizeof out, &n)
          == ZTEMPLATE_OK);
    CHECK(strcmp(out, "1+1=1") == 0);
    CHECK(ztemplate_var_count(tp) == 1);
    ztemplate_free(tp);
}

static void test_comments(void)
{
    const char *t = "a{{! this is a comment }}b{{!}}{{x}}";
    ztemplate *tp = ztemplate_parse(t, strlen(t), NULL);
    CHECK(tp != NULL);
    struct kv kvs[] = { { "x", "!" }, { 0, 0 } };
    char out[16];
    size_t n = 0;
    CHECK(ztemplate_render(tp, kv_lookup, kvs, out, sizeof out, &n)
          == ZTEMPLATE_OK);
    CHECK(strcmp(out, "ab!") == 0);
    ztemplate_free(tp);
}

static void test_parse_errors(void)
{
    size_t err = 0;
    CHECK(ztemplate_parse("open {{var", 10, &err) == NULL);
    CHECK(err == 5);
    CHECK(ztemplate_parse("empty {{}}", 10, &err) == NULL);
    CHECK(ztemplate_parse("blank {{  }}", 12, &err) == NULL);
    CHECK(ztemplate_parse("bad {{na me}}", 13, &err) == NULL);
    CHECK(ztemplate_parse("bad {{na$me}}", 13, &err) == NULL);
    /* a lone } or single { is literal text */
    ztemplate *tp = ztemplate_parse("a}b{c", 5, NULL);
    CHECK(tp != NULL);
    struct kv kvs[] = { { 0, 0 } };
    char out[8];
    size_t n = 0;
    CHECK(ztemplate_render(tp, kv_lookup, kvs, out, sizeof out, &n)
          == ZTEMPLATE_OK);
    CHECK(strcmp(out, "a}b{c") == 0);
    ztemplate_free(tp);
}

static void test_unknown_var_fails_closed(void)
{
    const char *t = "v={{missing}}";
    ztemplate *tp = ztemplate_parse(t, strlen(t), NULL);
    CHECK(tp != NULL);
    struct kv kvs[] = { { 0, 0 } };
    char out[64];
    size_t n = 0;
    CHECK(ztemplate_render(tp, kv_lookup, kvs, out, sizeof out, &n)
          == ZTEMPLATE_UNKNOWN_VAR);
    ztemplate_free(tp);
}

static void test_overflow_reports_size(void)
{
    const char *t = "[{{big}}]";
    ztemplate *tp = ztemplate_parse(t, strlen(t), NULL);
    CHECK(tp != NULL);
    struct kv kvs[] = { { "big", "0123456789" }, { 0, 0 } };
    size_t need = 0;
    CHECK(ztemplate_render(tp, kv_lookup, kvs, NULL, 0, &need)
          == ZTEMPLATE_OVERFLOW);
    CHECK(need == 12);
    char small[5];
    size_t n = 0;
    CHECK(ztemplate_render(tp, kv_lookup, kvs, small, sizeof small, &n)
          == ZTEMPLATE_OVERFLOW);
    CHECK(n == 12);
    CHECK(small[4] == '\0'); /* truncated output stays terminated */
    char boundary[12];
    CHECK(ztemplate_render(tp, kv_lookup, kvs, boundary, sizeof boundary, &n)
          == ZTEMPLATE_OVERFLOW);
    char *exact = malloc(need + 1);
    CHECK(exact != NULL);
    CHECK(ztemplate_render(tp, kv_lookup, kvs, exact, need + 1, &n)
          == ZTEMPLATE_OK);
    CHECK(strcmp(exact, "[0123456789]") == 0);
    free(exact);
    ztemplate_free(tp);
}

struct collect { char names[16][32]; size_t n; };

static bool collect_one(const char *name, size_t len, void *ctx)
{
    struct collect *c = ctx;
    CHECK(c->n < 16);
    memcpy(c->names[c->n], name, len);
    c->names[c->n][len] = '\0';
    c->n++;
    return true;
}

static void test_foreach_dedup(void)
{
    const char *t = "{{a}}{{b}}{{a}}{{c}}{{b}}";
    ztemplate *tp = ztemplate_parse(t, strlen(t), NULL);
    CHECK(tp != NULL);
    struct collect c = { .n = 0 };
    CHECK(ztemplate_foreach_var(tp, collect_one, &c));
    CHECK(c.n == 3);
    CHECK(strcmp(c.names[0], "a") == 0);
    CHECK(strcmp(c.names[1], "b") == 0);
    CHECK(strcmp(c.names[2], "c") == 0);
    ztemplate_free(tp);
}

/* Differential: build random templates from a fragment alphabet,
 * render with the library and with a naive reference, compare. */
static unsigned long long rng_state;

static unsigned long long rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

/* Trim spaces and tabs around the tag body between *nb and *ne. */
static void ref_trim_tag(const char *t, size_t *nb, size_t *ne)
{
    while (*nb < *ne && (t[*nb] == ' ' || t[*nb] == '\t')) (*nb)++;
    while (*ne > *nb && (t[*ne - 1] == ' ' || t[*ne - 1] == '\t')) (*ne)--;
}

/* Copy the value bound to the tag name t[nb..ne), if any, into out;
 * return the output offset after the copy. */
static size_t ref_append_var(const struct kv *kvs, const char *t,
                             size_t nb, size_t ne, char *out,
                             size_t cap, size_t o)
{
    for (size_t i = 0; kvs[i].k; i++) {
        if (strlen(kvs[i].k) == ne - nb &&
            memcmp(kvs[i].k, t + nb, ne - nb) == 0) {
            for (const char *v = kvs[i].v; *v && o + 1 < cap;)
                out[o++] = *v++;
            break;
        }
    }
    return o;
}

/* reference renderer: left-to-right scan */
static void ref_render(const char *t, const struct kv *kvs,
                       char *out, size_t cap)
{
    size_t o = 0;
    for (size_t p = 0; t[p];) {
        if (t[p] == '{' && t[p + 1] == '{') {
            const char *close = strstr(t + p + 2, "}}");
            CHECK(close != NULL);
            size_t nb = p + 2, ne = (size_t)(close - t);
            size_t next = ne + 2;
            if (t[nb] == '!') { p = next; continue; }
            ref_trim_tag(t, &nb, &ne);
            o = ref_append_var(kvs, t, nb, ne, out, cap, o);
            p = next;
        } else {
            if (o + 1 < cap) out[o++] = t[p];
            p++;
        }
    }
    out[o] = '\0';
}

static void test_differential(void)
{
    rng_state = 0xDEADBEEFCAFEF00Dull;
    static const char *frags[] = {
        "lit ", "{{a}}", "{{ b }}", "{{c}}", "{{! note }}",
        "{}", "} }", "x", "\t", "end."
    };
    struct kv kvs[] = {
        { "a", "A" }, { "b", "bee" }, { "c", "" }, { 0, 0 }
    };
    for (int iter = 0; iter < 3000; iter++) {
        char t[256];
        t[0] = '\0';
        size_t parts = rng_next() % 8;
        for (size_t i = 0; i < parts; i++)
            strcat(t, frags[rng_next() % 10]);
        ztemplate *tp = ztemplate_parse(t, strlen(t), NULL);
        CHECK(tp != NULL);
        char got[1024], want[1024];
        size_t n = 0;
        CHECK(ztemplate_render(tp, kv_lookup, kvs, got, sizeof got, &n)
              == ZTEMPLATE_OK);
        ref_render(t, kvs, want, sizeof want);
        if (strcmp(got, want) != 0) {
            fprintf(stderr, "iter %d got='%s' want='%s'\nt=", iter, got, want);
            for (const char *q = t; *q; q++) fprintf(stderr, "%02x ", (unsigned char)*q);
            fprintf(stderr, "\n");
            exit(1);
        }
        ztemplate_free(tp);
    }
}

static void test_parse_size_overflow(void)
{
    CHECK(ztemplate_parse("", SIZE_MAX, NULL) == NULL);
}

static bool huge_lookup(const char *name, size_t name_len,
                        const char **value, size_t *value_len, void *ctx)
{
    (void)name;
    (void)name_len;
    (void)ctx;
    /* Synthetic length metadata exercises arithmetic without allocating
     * an impossible span. Size-only rendering never reads this value. */
    *value = "v";
    *value_len = SIZE_MAX;
    return true;
}

static void test_render_size_overflow(void) {
    ztemplate *tp = ztemplate_parse("p{{big}}x", 9, NULL);
    CHECK(tp != NULL);
    size_t n = 99;
    CHECK(ztemplate_render(tp, huge_lookup, NULL, NULL, 0, &n)
          == ZTEMPLATE_OVERFLOW && n == SIZE_MAX);
    char out[6];
    memset(out, '!', sizeof out);
    CHECK(ztemplate_render(tp, huge_lookup, NULL, out, 4, &n)
          == ZTEMPLATE_OVERFLOW && n == SIZE_MAX &&
          out[0] == 'p' && out[1] == '\0' &&
          out[2] == '!' && out[3] == '!' &&
          out[4] == '!' && out[5] == '!');
    ztemplate_free(tp);
}

static void test_owned_text_allocation(void)
{
    CHECK(ztemplate_parse("x", SIZE_MAX, NULL) == NULL);
}

/* Exercise the real parser with deterministic successful zero-size allocation. */
static unsigned template_allocation_calls;
static size_t template_allocation_request;
static unsigned template_realloc_calls;
static bool template_refuse_realloc;

static void *template_fixture_malloc(size_t bytes) {
    size_t request = bytes ? bytes : 1;
    template_allocation_calls++;
    template_allocation_request = request;
    return malloc(request);
}

/* Boundary probes refuse before touching their artificial pointer; the only
 * successful fixture growth is initial allocation from NULL. */
static void *template_fixture_realloc(void *ptr, size_t bytes) {
    template_realloc_calls++;
    if (template_refuse_realloc) return NULL;
    CHECK(ptr == NULL);
    return template_fixture_malloc(bytes);
}

static void *template_fixture_calloc(size_t count, size_t bytes) {
    size_t total;
    if (ckd_mul(&total, count, bytes)) return NULL;
    void *memory = template_fixture_malloc(total);
    if (memory) memset(memory, 0, total);
    return memory;
}

void fixture_template_free(ztemplate *tp);
#define ztemplate_parse fixture_template_parse
#define ztemplate_free fixture_template_free
#define ztemplate_render fixture_template_render
#define ztemplate_var_count fixture_template_var_count
#define ztemplate_foreach_var fixture_template_foreach_var
#define malloc template_fixture_malloc
#define calloc template_fixture_calloc
#define realloc template_fixture_realloc
#include "../src/ztemplate.c"
#undef realloc
#undef calloc
#undef malloc
#undef ztemplate_parse
#undef ztemplate_free
#undef ztemplate_render
#undef ztemplate_var_count
#undef ztemplate_foreach_var

static void test_allocation_free_extent_refusal(void) {
    template_allocation_calls = 0;
    size_t position = 17;
    CHECK(fixture_template_parse("x", SIZE_MAX, &position) == NULL);
    CHECK(template_allocation_calls == 0);
    CHECK(position == 17);
    template_allocation_request = 0;
    void *zero = template_fixture_malloc(0);
    CHECK(zero != NULL);
    CHECK(template_allocation_request == 1);
    free(zero);
    template_allocation_calls = 0;
    ztemplate *empty = fixture_template_parse(NULL, 0, NULL);
    CHECK(empty != NULL);
    CHECK(template_allocation_calls == 2);
    fixture_template_free(empty);
}

static void test_segment_growth_bounds(void) {
    static const size_t capacities[] = {
        SIZE_MAX / 2 + 1, SIZE_MAX / (2 * sizeof(segment)) + 1};
    for (size_t i = 0; i < sizeof capacities / sizeof capacities[0]; i++) {
        segment marker = {SEG_VAR, 3, 7};
        ztemplate tp = {NULL, &marker, capacities[i], capacities[i]};
        template_realloc_calls = 0;
        template_refuse_realloc = true;
        CHECK(!seg_push(&tp, SEG_VAR, 4, 1));
        template_refuse_realloc = false;
        CHECK(template_realloc_calls == 0);
        CHECK(tp.segs == &marker && tp.nsegs == capacities[i] &&
              tp.cap_segs == capacities[i]);
        CHECK(marker.kind == SEG_VAR && marker.off == 3 && marker.len == 7);
    }
    ztemplate tp = {0};
    template_realloc_calls = 0;
    CHECK(seg_push(&tp, SEG_VAR, 3, 7));
    CHECK(template_realloc_calls == 1 && tp.nsegs == 1 && tp.cap_segs == 16);
    CHECK(tp.segs != NULL);
    CHECK(tp.segs[0].kind == SEG_VAR && tp.segs[0].off == 3 && tp.segs[0].len == 7);
    free(tp.segs);
}


static void test_cli(void);

int main(void)
{
    test_cli();
    test_allocation_free_extent_refusal();
    test_segment_growth_bounds();
    test_owned_text_allocation();
    test_render_size_overflow();
    test_parse_size_overflow();
    test_basic_render();
    test_whitespace_and_reuse();
    test_comments();
    test_parse_errors();
    test_unknown_var_fails_closed();
    test_overflow_reports_size();
    test_foreach_dedup();
    test_differential();
    puts("test_ztemplate: all groups passed (basic ws comments parseerr unknown overflow foreach diff)");
    return 0;
}

static FILE *cli_source, *cli_sink, *cli_errors;
static size_t cli_live, cli_parse_calls, cli_flushes;
static bool cli_read_fault;
static FILE *real_stdin(void) { return stdin; }
static FILE *real_stdout(void) { return stdout; }
static FILE *real_stderr(void) { return stderr; }
static ztemplate *cli_parse(const char *text, size_t len, size_t *err)
{
    cli_parse_calls++;
    ztemplate *tp = ztemplate_parse(text, len, err);
    if (tp) cli_live++;
    return tp;
}
static void cli_free(ztemplate *tp)
{
    CHECK(tp != NULL && cli_live > 0);
    ztemplate_free(tp);
    cli_live--;
}
[[maybe_unused]] static int cli_error(FILE *stream)
{
    return (stream == cli_source && cli_read_fault) || ferror(stream);
}
[[maybe_unused]] static int cli_flush(FILE *stream)
{
    if (stream == cli_sink) cli_flushes++;
    return fflush(stream);
}
#undef stdin
#undef stdout
#undef stderr
#define stdin cli_source
#define stdout cli_sink
#define stderr cli_errors
#define ferror cli_error
#define fflush cli_flush
#define ztemplate_parse cli_parse
#define ztemplate_free cli_free
#define main embedded_cli_main
#include "../app/main.c"
#undef main
#undef ztemplate_free
#undef ztemplate_parse
#undef fflush
#undef ferror
#undef stdin
#undef stdout
#undef stderr
#define stdin real_stdin()
#define stdout real_stdout()
#define stderr real_stderr()

static void cli_arguments(int argc, const char *const *args, char **copy, size_t cap)
{
    CHECK(argc >= 0 && (size_t)argc < cap);
    for (int i = 0; i < argc; i++) {
        copy[i] = malloc(strlen(args[i]) + 1);
        CHECK(copy[i] != NULL);
        memcpy(copy[i], args[i], strlen(args[i]) + 1);
    }
    copy[argc] = NULL;
}
static int cli_invoke(FILE *source, FILE *sink, FILE *errors,
                       int argc, const char *const *args)
{
    char *copy[260];
    cli_arguments(argc, args, copy, sizeof copy / sizeof copy[0]);
    cli_source = source;
    cli_sink = sink;
    cli_errors = errors;
    cli_live = cli_parse_calls = cli_flushes = 0;
    int rc = embedded_cli_main(argc, copy);
    cli_source = stdin;
    cli_sink = stdout;
    cli_errors = stderr;
    for (int i = 0; i < argc; i++) free(copy[i]);
    CHECK(cli_live == 0);
    return rc;
}
static FILE *cli_input(const void *bytes, size_t n)
{
    FILE *source = tmpfile();
    CHECK(source != NULL);
    CHECK(fwrite(bytes, 1, n, source) == n && fflush(source) == 0);
    rewind(source);
    return source;
}
static void cli_message(FILE *stream, const char *want)
{
    char bytes[256];
    rewind(stream);
    size_t n = fread(bytes, 1, sizeof bytes - 1, stream);
    bytes[n] = '\0';
    CHECK(!ferror(stream) && strstr(bytes, want) != NULL);
}
static void cli_case(const char *input, int argc, const char *const *args,
                      int status, const char *want, const char *message)
{
    FILE *source = cli_input(input, strlen(input));
    FILE *sink = tmpfile(), *errors = tmpfile();
    CHECK(sink != NULL && errors != NULL);
    CHECK(cli_invoke(source, sink, errors, argc, args) == status);
    if (!*want) { CHECK(cli_flushes == 0); }
    char bytes[256];
    rewind(sink);
    size_t n = fread(bytes, 1, sizeof bytes, sink);
    CHECK(!ferror(sink) && n == strlen(want) && !memcmp(bytes, want, n));
    if (message) { cli_message(errors, message); }
    CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_binary_boundary(size_t length, int status, bool argument)
{
    static unsigned char bytes[65537];
    memset(bytes, argument ? 'a' : 0, sizeof bytes);
    bytes[length - 1] = 'Z';
    bytes[length] = 0;
    FILE *source = cli_input(bytes, argument ? 0 : length), *sink = tmpfile(), *errors = tmpfile();
    CHECK(sink != NULL && errors != NULL);
    const char *args[] = {"ztemplate", "-t", (const char *)bytes};
    CHECK(cli_invoke(source, sink, errors, argument ? 3 : 1, args) == status);
    if (status) { CHECK(cli_flushes == 0 && ftell(sink) == 0); }
    else {
        rewind(sink);
        unsigned char got[4096];
        size_t offset = 0;
        while (offset < length) {
            size_t want = length - offset < sizeof got ? length - offset : sizeof got;
            CHECK(fread(got, 1, want, sink) == want && !memcmp(got, bytes + offset, want));
            offset += want;
        }
        CHECK(fgetc(sink) == EOF && !ferror(sink));
    }
    CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_bindings(void)
{
    char bindings[256][32];
    const char *args[259] = {"ztemplate", "-t", "{{k254}}"};
    for (size_t i = 0; i < 256; i++) {
        snprintf(bindings[i], sizeof bindings[i], "k%zu=value%zu", i, i);
        args[i + 3] = bindings[i];
    }
    cli_case("", 258, args, 0, "value254", NULL);
    cli_case("", 259, args, 2, "", "too many bindings");
    args[258] = "malformed";
    cli_case("", 259, args, 2, "", "too many bindings");
    args[2] = "{{";
    cli_case("", 259, args, 2, "", "parse error");
}
static void cli_controls(void)
{
    const char *normal[] = {"ztemplate", "-t", "Hi {{x}}{{! drop}}.", "x=A", "x=B"};
    cli_case("", 5, normal, 0, "Hi A.", NULL);
    const char *input[] = {"ztemplate", "x=A", "empty="};
    cli_case("{{x}}/{{empty}}", 3, input, 0, "A/", NULL);
    const char *unknown[] = {"ztemplate", "-t", "{{missing}}"};
    cli_case("", 3, unknown, 1, "", "render failed");
    const char *parse[] = {"ztemplate", "-t", "{{"};
    cli_case("", 3, parse, 2, "", "parse error");
    const char *bad[] = {"ztemplate", "-t", "literal", "bad"};
    cli_case("", 4, bad, 2, "", "bad binding");
    const char *missing[] = {"ztemplate", "-t"};
    cli_case("literal", 2, missing, 2, "", "bad binding");
    const char *empty[] = {"ztemplate", "-t", ""};
    cli_case("", 3, empty, 0, "", NULL);
    cli_case("", 1, empty, 0, "", NULL);
}
static void cli_render_bound(void)
{
    char text[1281], binding[4099];
    for (size_t i = 0; i < 256; i++) memcpy(text + i * 5, "{{x}}", 5);
    text[1280] = '\0';
    memcpy(binding, "x=", 2);
    memset(binding + 2, 'a', 4096);
    binding[4098] = '\0';
    const char *args[] = {"ztemplate", "-t", text, binding};
    cli_case("", 4, args, 2, "", "rendered output too long");
}
static void cli_read_errors(void)
{
    const char *args[] = {"ztemplate"};
    cli_read_fault = true;
    cli_case("valid", 1, args, 2, "", "read error");
    CHECK(cli_parse_calls == 0);
    cli_read_fault = false;
#ifdef _WIN32
    FILE *source = fopen("NUL", "w");
#else
    FILE *source = fopen("/dev/null", "w");
#endif
    FILE *sink = tmpfile(), *errors = tmpfile();
    CHECK(source != NULL && sink != NULL && errors != NULL);
    CHECK(cli_invoke(source, sink, errors, 1, args) == 2 && cli_parse_calls == 0);
    CHECK(ftell(sink) == 0 && cli_flushes == 0);
    CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_failed_sink(bool buffered)
{
#ifdef _WIN32
    const char *null_path = "NUL";
#else
    const char *null_path = "/dev/null";
#endif
    FILE *source = cli_input("", 0), *errors = tmpfile();
    FILE *sink = fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r");
    CHECK(sink != NULL && errors != NULL);
    char buffer[4096];
    if (buffered) { CHECK(setvbuf(sink, buffer, _IOFBF, sizeof buffer) == 0); }
    const char *args[] = {"ztemplate", "-t", "abc"};
    CHECK(cli_invoke(source, sink, errors, 3, args) == 1 && ferror(sink));
    cli_message(errors, "write error");
    CHECK(fclose(source) == 0 && fclose(errors) == 0);
    (void)fclose(sink);
}
static void test_cli(void)
{
    cli_controls();
    cli_binary_boundary(65534, 0, false);
    cli_binary_boundary(65535, 0, false);
    cli_binary_boundary(65536, 2, false);
    cli_binary_boundary(65535, 0, true);
    cli_binary_boundary(65536, 2, true);
    cli_bindings();
    cli_render_bound();
    cli_read_errors();
    cli_failed_sink(false);
#ifdef __linux__
    cli_failed_sink(true);
#endif
}
