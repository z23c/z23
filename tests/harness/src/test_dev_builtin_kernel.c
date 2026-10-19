/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The built-in guest kernel: deterministic packing, verified
 *          unpacking with named refusals, the documented pin, and the boot
 *          command's built_in selector. Synthetic kernels stand in for the
 *          62 MB release kernel, which no test embeds. */
#include "test/test_core.h"
#include "base/hex.h"
#include "command/native_builtin_kernel.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BK_SYNTH_BYTES 300000u
#define BK_PATH "dev.app.machine.boot"

static uint8_t bk_synth[BK_SYNTH_BYTES];
static char bk_synth_hex[2 * SHA256_OUTPUT_SIZE + 1];

/* Mixed content: a pseudo-random half that does not compress and a zero half. */
static void bk_make_synth(void)
{
    uint32_t x = 0x2545f491u;
    struct sha256_ctx ctx;
    uint8_t digest[SHA256_OUTPUT_SIZE];
    for (size_t i = 0; i < BK_SYNTH_BYTES / 2u; i++) {
        x = x * 1664525u + 1013904223u;
        bk_synth[i] = (uint8_t)(x >> 24);
    }
    memset(bk_synth + BK_SYNTH_BYTES / 2u, 0, BK_SYNTH_BYTES / 2u);
    sha256_init(&ctx);
    sha256_write(&ctx, bk_synth, sizeof bk_synth);
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof digest, bk_synth_hex);
}

static struct zcl_builtin_kernel_pin bk_synth_pin(void)
{
    struct zcl_builtin_kernel_pin pin = {BK_SYNTH_BYTES, bk_synth_hex};
    return pin;
}

/* Unpacks gz against pin; the buffer must exist exactly when the status is OK. */
static enum zcl_builtin_kernel_status bk_unpack(const uint8_t *gz, size_t gz_size,
                                                const struct zcl_builtin_kernel_pin *pin,
                                                bool *buffer_ok)
{
    uint8_t *out = (uint8_t *)1;
    size_t length = 1;
    enum zcl_builtin_kernel_status s = zcl_builtin_kernel_unpack(gz, gz_size, pin, &out, &length);
    *buffer_ok = s == ZCL_BUILTIN_KERNEL_OK
                     ? out != NULL && length == pin->length && memcmp(out, bk_synth, length) == 0
                     : out == NULL && length == 0;
    if (s == ZCL_BUILTIN_KERNEL_OK) free(out);
    return s;
}

static bool bk_refused(const uint8_t *gz, size_t gz_size,
                       const struct zcl_builtin_kernel_pin *pin,
                       enum zcl_builtin_kernel_status want)
{
    bool buffer_ok = false;
    return bk_unpack(gz, gz_size, pin, &buffer_ok) == want && buffer_ok;
}

static bool bk_round_trip_case(void)
{
    struct zcl_builtin_kernel_pin pin = bk_synth_pin();
    size_t a_size = 0, b_size = 0;
    uint8_t *a = zcl_builtin_kernel_pack(bk_synth, sizeof bk_synth, &a_size);
    uint8_t *b = zcl_builtin_kernel_pack(bk_synth, sizeof bk_synth, &b_size);
    bool ok = a != NULL && b != NULL && a_size == b_size && a_size < sizeof bk_synth &&
              memcmp(a, b, a_size) == 0 && a[0] == 0x1f && a[1] == 0x8b &&
              memcmp(a + 4, "\0\0\0\0", 4) == 0;
    bool buffer_ok = false;
    ok = ok && bk_unpack(a, a_size, &pin, &buffer_ok) == ZCL_BUILTIN_KERNEL_OK && buffer_ok;
    free(a);
    free(b);
    return ok;
}

/* A valid member followed by one extra byte, or by a second valid member. */
static bool bk_trailing_case(const uint8_t *gz, size_t size,
                             const struct zcl_builtin_kernel_pin *pin)
{
    uint8_t *two = malloc(2u * size + 1u);
    bool ok = two != NULL;
    if (!ok) return false;
    memcpy(two, gz, size);
    two[size] = 0;
    ok = bk_refused(two, size + 1u, pin, ZCL_BUILTIN_KERNEL_INFLATE_FAILED);
    memcpy(two + size, gz, size);
    ok = ok && bk_refused(two, 2u * size, pin, ZCL_BUILTIN_KERNEL_INFLATE_FAILED);
    free(two);
    return ok;
}

static bool bk_damaged_case(void)
{
    struct zcl_builtin_kernel_pin pin = bk_synth_pin();
    size_t size = 0;
    uint8_t *gz = zcl_builtin_kernel_pack(bk_synth, sizeof bk_synth, &size);
    bool ok = gz != NULL;
    if (!ok) return false;
    ok = bk_refused(gz, size - 20u, &pin, ZCL_BUILTIN_KERNEL_INFLATE_FAILED) &&
         bk_refused(gz, 12u, &pin, ZCL_BUILTIN_KERNEL_INFLATE_FAILED);
    gz[size / 2u] ^= 0x40u;
    ok = ok && bk_refused(gz, size, &pin, ZCL_BUILTIN_KERNEL_INFLATE_FAILED);
    gz[size / 2u] ^= 0x40u;
    gz[size - 1u] ^= 0x01u; /* the recorded length */
    ok = ok && bk_refused(gz, size, &pin, ZCL_BUILTIN_KERNEL_INFLATE_FAILED);
    gz[size - 1u] ^= 0x01u;
    ok = ok && bk_trailing_case(gz, size, &pin);
    ok = ok && bk_refused(gz, 0, &pin, ZCL_BUILTIN_KERNEL_ABSENT) &&
         bk_refused(NULL, size, &pin, ZCL_BUILTIN_KERNEL_ABSENT);
    free(gz);
    return ok;
}

static bool bk_pin_case(void)
{
    struct zcl_builtin_kernel_pin pin = bk_synth_pin();
    struct zcl_builtin_kernel_pin longer = pin, shorter = pin, other = pin, huge = pin;
    char wrong[2 * SHA256_OUTPUT_SIZE + 1];
    size_t size = 0;
    uint8_t *gz = zcl_builtin_kernel_pack(bk_synth, sizeof bk_synth, &size);
    bool ok = gz != NULL;
    if (!ok) return false;
    memcpy(wrong, bk_synth_hex, sizeof wrong);
    wrong[0] = wrong[0] == '0' ? '1' : '0';
    longer.length++;
    shorter.length--;
    other.sha256_hex = wrong;
    huge.length = ZCL_BUILTIN_KERNEL_MAX_BYTES + 1u;
    ok = bk_refused(gz, size, &longer, ZCL_BUILTIN_KERNEL_LENGTH_MISMATCH) &&
         bk_refused(gz, size, &shorter, ZCL_BUILTIN_KERNEL_TOO_LARGE) &&
         bk_refused(gz, size, &other, ZCL_BUILTIN_KERNEL_HASH_MISMATCH) &&
         bk_refused(gz, size, &huge, ZCL_BUILTIN_KERNEL_TOO_LARGE);
    free(gz);
    return ok;
}

/* A stream far larger than the pin is stopped at pin length + 1. */
static bool bk_bomb_case(void)
{
    static const struct zcl_builtin_kernel_pin small = {
        1000, "0000000000000000000000000000000000000000000000000000000000000000"};
    size_t size = 0, big = (size_t)64 << 20;
    uint8_t *zeros = calloc(1, big);
    uint8_t *gz = zeros != NULL ? zcl_builtin_kernel_pack(zeros, big, &size) : NULL;
    bool ok = gz != NULL && size < ((size_t)1 << 17);
    uint8_t *out = (uint8_t *)1;
    size_t length = 1;
    ok = ok && zcl_builtin_kernel_unpack(gz, size, &small, &out, &length) ==
                   ZCL_BUILTIN_KERNEL_TOO_LARGE && out == NULL && length == 0;
    free(gz);
    free(zeros);
    return ok;
}

static bool bk_names_case(void)
{
    return strcmp(zcl_builtin_kernel_status_name(ZCL_BUILTIN_KERNEL_ABSENT), "builtin_kernel_absent") == 0 &&
           strcmp(zcl_builtin_kernel_status_name(ZCL_BUILTIN_KERNEL_INFLATE_FAILED), "builtin_kernel_inflate_failed") == 0 &&
           strcmp(zcl_builtin_kernel_status_name(ZCL_BUILTIN_KERNEL_LENGTH_MISMATCH), "builtin_kernel_length_mismatch") == 0 &&
           strcmp(zcl_builtin_kernel_status_name(ZCL_BUILTIN_KERNEL_HASH_MISMATCH), "builtin_kernel_hash_mismatch") == 0 &&
           strcmp(zcl_builtin_kernel_status_name(ZCL_BUILTIN_KERNEL_TOO_LARGE), "builtin_kernel_too_large") == 0;
}

static bool bk_read(const char *path, char **text)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    *text = calloc(1, (size_t)1 << 22);
    if (f == NULL || *text == NULL) {
        if (f != NULL) fclose(f);
        return false;
    }
    n = fread(*text, 1, ((size_t)1 << 22) - 1u, f);
    fclose(f);
    return n > 0;
}

/* The pin equals the documented row, and the release test's constants. */
static bool bk_pin_documented_case(void)
{
    char row[160], bytes[32];
    char *doc = NULL, *release = NULL;
    const char *line;
    bool ok = bk_read("docs/commons/RISCV_MACHINE.md", &doc) &&
              bk_read("tests/harness/src/test_rvmachine_freebsd_release.c", &release);
    snprintf(bytes, sizeof bytes, "UINT64_C(%llu)", (unsigned long long)ZCL_BUILTIN_KERNEL_BYTES);
    snprintf(row, sizeof row, "| KERNEL: release GENERIC kernel | %llu | `%s` |",
             (unsigned long long)ZCL_BUILTIN_KERNEL_BYTES, ZCL_BUILTIN_KERNEL_SHA256);
    line = ok ? strstr(doc, "| KERNEL: release GENERIC kernel |") : NULL;
    ok = ok && line != NULL && strncmp(line, row, strlen(row)) == 0 &&
         strstr(release, bytes) != NULL && strstr(release, ZCL_BUILTIN_KERNEL_SHA256) != NULL &&
         zcl_builtin_kernel_release_pin()->length == ZCL_BUILTIN_KERNEL_BYTES &&
         strcmp(zcl_builtin_kernel_release_pin()->sha256_hex, ZCL_BUILTIN_KERNEL_SHA256) == 0;
    free(doc);
    free(release);
    return ok;
}

struct bk_call {
    struct json_value doc;
    enum zcl_command_exit exit_code;
    bool parsed;
};

static bool bk_boot(struct bk_call *c, const char *json)
{
    static char wire[16384];
    const struct zcl_command_spec *found =
        zcl_command_registry_find(zcl_command_catalog(), BK_PATH, NULL);
    struct zcl_command_spec spec;
    struct json_value input;
    size_t len = 0;
    json_init(&c->doc);
    json_init(&input);
    c->exit_code = ZCL_COMMAND_EXIT_OK;
    if (found == NULL) return false;
    spec = *found;
    spec.handler = zcl_native_handle_dev_machine_boot;
    if (json_read(&input, json, strlen(json)) && input.type == JSON_OBJ)
        len = zcl_command_registry_execute_json(zcl_command_catalog(), &spec, NULL, &input,
                                                false, BK_PATH, NULL, 0, 0, NULL, wire,
                                                sizeof wire, &c->exit_code);
    json_free(&input);
    c->parsed = len > 0 && json_read(&c->doc, wire, len);
    return c->parsed;
}

static bool bk_error_is(const struct bk_call *c, const char *code, const char *text)
{
    const struct json_value *error = json_get(&c->doc, "error");
    const char *got = json_get_str(json_get(error, "code"));
    const char *message = json_get_str(json_get(error, "message"));
    return c->parsed && !json_get_bool(json_get(&c->doc, "ok")) &&
           c->exit_code != ZCL_COMMAND_EXIT_OK && json_get(&c->doc, "data") == NULL &&
           got != NULL && strcmp(got, code) == 0 &&
           (text == NULL || (message != NULL && strstr(message, text) != NULL));
}

static bool bk_refuses(const char *json, const char *code, const char *text)
{
    struct bk_call c;
    bool ok = bk_boot(&c, json) && bk_error_is(&c, code, text);
    json_free(&c.doc);
    return ok;
}

/* A well-formed PUBLIC unlock row still needs the installed PUBLIC image. */
static bool bk_public_unlock_case(void)
{
    return bk_refuses("{\"builtin_kernel\":true,\"entropy\":\"host\",\"early_seed\":\"host\","
                      "\"public_unlock\":{\"policy\":\"public_keyfile_fixture\","
                      "\"purpose\":\"public_geli_keyfile\",\"receiver_revision\":1,"
                      "\"mode\":\"initial\",\"authorized_kernel_sha256\":"
                      "\"2445a0ca747bb28eac52c8c2bb861ee9be06f3c7353587d88e3c3fcbb832b2f4\","
                      "\"volume\":\"v\",\"record\":\"r\",\"credential\":\"c\"}}",
                      "INVALID_INPUT", "PUBLIC unlock requires an installed");
}

static bool bk_write(const char *path)
{
    FILE *f = fopen(path, "wb");
    bool ok = f != NULL && fputs("x", f) >= 0;
    if (f != NULL) ok = fclose(f) == 0 && ok;
    return ok;
}

/* ports with builtin_kernel pass the selector checks: a default build then
 * refuses the absent kernel by name, a build with the kernel runs it. */
static bool bk_ports_case(void)
{
    char dir[256], in[320], ex[320], json[1024];
    struct bk_call c;
    bool ok;
    if (test_mkdtemp(dir, sizeof dir, "builtin_kernel_ports") == NULL) return false;
    snprintf(in, sizeof in, "%s/in", dir);
    snprintf(ex, sizeof ex, "%s/ex", dir);
    snprintf(json, sizeof json, "{\"builtin_kernel\":true,\"max_instr\":1000,\"ports\":"
             "[{\"name\":\"P\",\"input\":\"%s\",\"expect\":\"%s\"}]}", in, ex);
    ok = bk_write(in) && bk_write(ex) && bk_boot(&c, json);
    if (ok && zcl_builtin_kernel_gz_size == 0) ok = bk_error_is(&c, "BUILTIN_KERNEL_ABSENT", NULL);
    else if (ok) ok = !bk_error_is(&c, "INVALID_INPUT", NULL);
    json_free(&c.doc);
    test_cleanup_tmpdir(dir);
    return ok;
}

static bool bk_command_case(void)
{
    return bk_refuses("{\"kernel\":\"/nonexistent\",\"builtin_kernel\":true}",
                      "INVALID_INPUT", "exactly one of kernel") &&
           bk_refuses("{\"builtin_kernel\":true,\"accepted_kernel\":{}}",
                      "INVALID_INPUT", "builtin_kernel") &&
           bk_refuses("{\"builtin_kernel\":true,\"public_kernel\":{}}",
                      "INVALID_INPUT", "builtin_kernel") &&
           bk_refuses("{\"builtin_kernel\":false}", "INVALID_INPUT", "builtin_kernel must be true") &&
           bk_public_unlock_case() && bk_ports_case();
}

/* A default build refuses the selector by name; a build with the kernel
 * unpacks it against the documented pin. */
static bool bk_embedded_case(void)
{
    uint8_t *out = NULL;
    size_t length = 0;
    enum zcl_builtin_kernel_status s = zcl_builtin_kernel_load(&out, &length);
    if (zcl_builtin_kernel_gz_size == 0)
        return s == ZCL_BUILTIN_KERNEL_ABSENT && out == NULL &&
               bk_refuses("{\"builtin_kernel\":true,\"max_instr\":1000}",
                          "BUILTIN_KERNEL_ABSENT", "builtin_kernel_absent");
    bool ok = s == ZCL_BUILTIN_KERNEL_OK && out != NULL && length == ZCL_BUILTIN_KERNEL_BYTES;
    free(out);
    return ok;
}

#define BK_CASE(fn, title, check)      \
    static int fn(void)                \
    {                                  \
        int failures = 0;              \
        TEST(title) {                  \
            ASSERT(check);             \
            PASS();                    \
        } _test_next:;                 \
        return failures;               \
    }

BK_CASE(t_round_trip, "built-in kernel: packing is deterministic and the round trip verifies",
        bk_round_trip_case())
BK_CASE(t_damaged, "built-in kernel: truncated, corrupted and empty blobs give named refusals",
        bk_damaged_case())
BK_CASE(t_pin, "built-in kernel: a wrong pinned length or hash gives a named refusal",
        bk_pin_case())
BK_CASE(t_bomb, "built-in kernel: a stream past the pin is stopped and refused", bk_bomb_case())
BK_CASE(t_names, "built-in kernel: refusal names are the documented ones", bk_names_case())
BK_CASE(t_documented, "built-in kernel: the pin equals the documented release kernel row",
        bk_pin_documented_case())
BK_CASE(t_command, "dev.app.machine.boot: builtin_kernel excludes the other kernel selectors",
        bk_command_case())
BK_CASE(t_embedded, "dev.app.machine.boot: builtin_kernel is refused by name when not compiled in",
        bk_embedded_case())

int test_dev_builtin_kernel(void);
int test_dev_builtin_kernel(void)
{
    bk_make_synth();
    return t_round_trip() + t_damaged() + t_pin() + t_bomb() + t_names() + t_documented() +
           t_command() + t_embedded();
}
