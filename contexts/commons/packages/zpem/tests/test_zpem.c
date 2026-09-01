/* zpem tests — hand-written known-answer, round-trip, and fault cases.
 *
 * Covers: a hand-computed exact wire form, round trips across base64
 * line-break boundaries (63/64/65-byte payloads), multi-block files
 * walked via `consumed`, strict rejections (label mismatch, bad
 * markers, foreign characters, illegal labels, truncation), and
 * capacity errors.
 */
#include "zpem/zpem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
      failures++;                                                       \
    }                                                                   \
  } while (0)

static void test_kat(void)
{
    /* "hi" is base64 "aGk=" — verified against the reference
     * `base64` tool and RFC 4648. */
    static const char want[] =
        "-----BEGIN X-----\n"
        "aGk=\n"
        "-----END X-----\n";
    char out[128];
    size_t out_len = 0;
    CHECK(zpem_encode("X", 1, (const uint8_t *)"hi", 2,
                      out, sizeof(out), &out_len) == ZPEM_OK);
    CHECK(out_len == strlen(want));
    CHECK(out_len == zpem_encoded_len(2, 1));
    CHECK(memcmp(out, want, out_len) == 0);

    /* Parse it back. */
    zpem_block blk;
    CHECK(zpem_parse(out, out_len, &blk) == ZPEM_OK);
    CHECK(blk.label_len == 1 && blk.label[0] == 'X');
    CHECK(blk.consumed == out_len);
    char scratch[64];
    uint8_t der[16];
    size_t der_len = 0;
    CHECK(zpem_decode(&blk, scratch, sizeof(scratch),
                      der, sizeof(der), &der_len) == ZPEM_OK);
    CHECK(der_len == 2 && der[0] == 'h' && der[1] == 'i');
}

static void test_roundtrip_boundaries(void)
{
    /* Sizes around the 48-byte (64-char) line boundary. */
    static const size_t sizes[] = { 0, 1, 2, 3, 47, 48, 49, 96, 97, 255 };
    uint8_t der[256];
    for (size_t i = 0; i < sizeof(der); i++) der[i] = (uint8_t)(i ^ 0x5au);

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        size_t n = sizes[s];
        size_t cap = zpem_encoded_len(n, 11);
        CHECK(cap > 0);
        char *pem = malloc(cap);
        CHECK(pem != NULL);
        size_t pem_len = 0;
        CHECK(zpem_encode("CERTIFICATE", 11, der, n,
                          pem, cap, &pem_len) == ZPEM_OK);
        CHECK(pem_len == cap);

        uint8_t back[256];
        size_t back_len = 0;
        char *scratch = malloc(cap);
        CHECK(scratch != NULL);
        zpem_block blk;
        CHECK(zpem_read(pem, pem_len, scratch, cap,
                        back, sizeof(back), &back_len, &blk) == ZPEM_OK);
        CHECK(blk.label_len == 11 &&
              memcmp(blk.label, "CERTIFICATE", 11) == 0);
        CHECK(blk.consumed == pem_len);
        CHECK(back_len == n);
        CHECK(memcmp(back, der, n) == 0);
        free(scratch);
        free(pem);
    }
}

static void test_line_layout(void)
{
    /* 49 bytes -> 68 base64 chars -> lines of 64 and 4. */
    uint8_t der[49];
    memset(der, 0xab, sizeof(der));
    size_t cap = zpem_encoded_len(sizeof(der), 1);
    char *pem = malloc(cap);
    CHECK(pem != NULL);
    size_t pem_len = 0;
    CHECK(zpem_encode("Z", 1, der, sizeof(der), pem, cap, &pem_len)
          == ZPEM_OK);
    /* First body line is exactly 64 chars + '\n'. */
    const char *body = strstr(pem, "-----\n");
    CHECK(body != NULL);
    body += 6;
    CHECK(body[64] == '\n');
    CHECK(body[65 + 4] == '\n'); /* second line: 4 chars + '\n' */
    free(pem);
}

static void test_multi_block(void)
{
    static const char two[] =
        "-----BEGIN A-----\n"
        "aGk=\n"
        "-----END A-----\n"
        "-----BEGIN B-----\n"
        "aGVsbG8=\n"
        "-----END B-----\n";
    size_t off = 0, total = strlen(two);
    const char *labels[] = { "A", "B" };
    const char *payloads[] = { "hi", "hello" };
    char scratch[64];
    for (int k = 0; k < 2; k++) {
        zpem_block blk;
        uint8_t der[16];
        size_t der_len = 0;
        CHECK(zpem_read(two + off, total - off, scratch, sizeof(scratch),
                        der, sizeof(der), &der_len, &blk) == ZPEM_OK);
        CHECK(blk.label_len == 1 && blk.label[0] == labels[k][0]);
        CHECK(der_len == strlen(payloads[k]));
        CHECK(memcmp(der, payloads[k], der_len) == 0);
        off += blk.consumed;
    }
    CHECK(off == total);
}

static void test_crlf(void)
{
    static const char crlf[] =
        "-----BEGIN X-----\r\n"
        "aGk=\r\n"
        "-----END X-----\r\n";
    zpem_block blk;
    char scratch[32];
    uint8_t der[8];
    size_t der_len = 0;
    CHECK(zpem_read(crlf, strlen(crlf), scratch, sizeof(scratch),
                    der, sizeof(der), &der_len, &blk) == ZPEM_OK);
    CHECK(der_len == 2 && der[0] == 'h' && der[1] == 'i');
    CHECK(blk.consumed == strlen(crlf));
}

static void test_rejects(void)
{
    struct { const char *pem; zpem_err err; } bad[] = {
        { "-----BEGIN X-----\naGk=\n-----END Y-----\n",
          ZPEM_ERR_FORMAT },                        /* label mismatch */
        { "----BEGIN X-----\naGk=\n-----END X-----\n",
          ZPEM_ERR_FORMAT },                        /* short marker */
        { "-----BEGIN X-----\naGk!\n-----END X-----\n",
          ZPEM_ERR_FORMAT },                        /* foreign char */
        { "-----BEGIN X-----\naGk \n-----END X-----\n",
          ZPEM_ERR_FORMAT },                        /* space in body */
        { "-----BEGIN X-----\naGk=\n-----END X-----",
          ZPEM_ERR_FORMAT },                        /* no final EOL */
        { "-----BEGIN X-----\naGk=\n",
          ZPEM_ERR_FORMAT },                        /* no END marker */
        { "-----BEGIN x-----\naGk=\n-----END x-----\n",
          ZPEM_ERR_LABEL },                         /* lowercase label */
        { "-----BEGIN -X-----\naGk=\n-----END -X-----\n",
          ZPEM_ERR_LABEL },                         /* leading dash */
        { "-----BEGIN -----\naGk=\n-----END -----\n",
          ZPEM_ERR_FORMAT },                        /* empty label */
        { "", ZPEM_ERR_FORMAT },
    };
    for (size_t k = 0; k < sizeof(bad) / sizeof(bad[0]); k++) {
        zpem_block blk;
        zpem_err e = zpem_parse(bad[k].pem, strlen(bad[k].pem), &blk);
        if (e != bad[k].err)
            fprintf(stderr, "  case %zu: got %s, want %s\n", k,
                    zpem_err_str(e), zpem_err_str(bad[k].err));
        CHECK(e == bad[k].err);
    }

    /* Bad base64 that passes the body character scan. */
    static const char badb64[] =
        "-----BEGIN X-----\n"
        "a==a\n"
        "-----END X-----\n";
    zpem_block blk;
    CHECK(zpem_parse(badb64, strlen(badb64), &blk) == ZPEM_OK);
    char scratch[32];
    uint8_t der[8];
    size_t der_len;
    CHECK(zpem_decode(&blk, scratch, sizeof(scratch),
                      der, sizeof(der), &der_len) == ZPEM_ERR_BASE64);
}

static void test_capacity(void)
{
    char out[64];
    size_t out_len;
    size_t need = zpem_encoded_len(2, 1);
    CHECK(need > 0);
    CHECK(zpem_encode("X", 1, (const uint8_t *)"hi", 2,
                      out, need - 1, &out_len) == ZPEM_ERR_CAP);
    CHECK(zpem_encode("X", 1, (const uint8_t *)"hi", 2,
                      out, need, &out_len) == ZPEM_OK);

    /* Scratch and der buffers too small. */
    static const char pem[] =
        "-----BEGIN X-----\naGk=\n-----END X-----\n";
    zpem_block blk;
    CHECK(zpem_parse(pem, strlen(pem), &blk) == ZPEM_OK);
    char scratch[3]; /* body is 5 bytes */
    uint8_t der[8];
    size_t der_len;
    CHECK(zpem_decode(&blk, scratch, sizeof(scratch),
                      der, sizeof(der), &der_len) == ZPEM_ERR_CAP);
    char scratch2[8];
    uint8_t tiny[1];
    CHECK(zpem_decode(&blk, scratch2, sizeof(scratch2),
                      tiny, sizeof(tiny), &der_len) == ZPEM_ERR_BASE64);
}

static void test_args_and_ranges(void)
{
    zpem_block blk;
    CHECK(zpem_parse(NULL, 4, &blk) == ZPEM_ERR_ARG);
    CHECK(zpem_parse("x", 1, NULL) == ZPEM_ERR_ARG);
    CHECK(zpem_encode(NULL, 1, NULL, 0, NULL, 0, NULL) == ZPEM_ERR_ARG);
    CHECK(zpem_encoded_len(4, 0) == 0);
    CHECK(zpem_encoded_len(4, ZPEM_MAX_LABEL + 1) == 0);
    /* 33-char label rejected at encode. */
    char longlabel[ZPEM_MAX_LABEL + 2];
    memset(longlabel, 'A', sizeof(longlabel));
    CHECK(zpem_encode(longlabel, ZPEM_MAX_LABEL + 1,
                      (const uint8_t *)"x", 1, NULL, 0, NULL)
          == ZPEM_ERR_RANGE);
    /* Label with an interior five-dash run. */
    CHECK(zpem_encode("A-----B", 7, (const uint8_t *)"x", 1,
                      NULL, 0, NULL) == ZPEM_ERR_LABEL);
    for (int e = 0; e <= 6; e++)
        CHECK(zpem_err_str((zpem_err)e) != NULL);
}

int main(void)
{
    test_kat();
    test_roundtrip_boundaries();
    test_line_layout();
    test_multi_block();
    test_crlf();
    test_rejects();
    test_capacity();
    test_args_and_ranges();
    if (failures) {
        fprintf(stderr, "zpem: %d failure(s)\n", failures);
        return 1;
    }
    puts("zpem: all tests passed");
    return 0;
}
