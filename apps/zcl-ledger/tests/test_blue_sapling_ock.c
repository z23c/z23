/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_sapling_ock.h"
#include "blue_sapling_aead.h"
#include "blue_sapling_kdf.h"
#include "blue_sapling_memo.h"
#include "blue_sapling_epk.h"
#include "blue_sapling_cm.h"
#include "blue_jubjub_decode.h"
#include "blue_jubjub_lowmem.h"
#include "blue_jubjub_arithmetic.h"
#include "blue_jubjub_encode.h"
#include "zcl_tx_shielded_replay.h"
#include "zcl_zip243_host.h"
#include "crypto/chacha20poly1305.h"
#include "support/log_throttle.h"
#include "base/log_level.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

enum { WIRE_BYTES = 1425, OUTPUT_OFFSET = 412 };

/* Host-only support for the independent core AEAD oracle. */
int64_t clock_now_wall_ms(void) { return 0; }
bool zcl_alloc_fault_should_fail(const char *label) {
    (void)label;
    return false;
}
void zcl_alloc_note_failure(void) {}
enum zcl_log_level zcl_log_level_get(void) { return ZCL_LOG_OFF; }
void zcl_log_emit_at(enum zcl_log_level level, const char *format, ...) {
    (void)level;
    (void)format;
}
bool log_throttle_should_emit(struct log_throttle *throttle, uint64_t key,
    int64_t now, int64_t interval, uint64_t *repetitions) {
    (void)throttle; (void)key; (void)now; (void)interval;
    (void)repetitions;
    return false;
}
void memory_cleanse(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static int hex_digit(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}

static void read_fixture(const char *path, uint8_t wire[WIRE_BYTES]) {
    FILE *file = fopen(path, "r");
    assert(file);
    char line[WIRE_BYTES * 2 + 2];
    do {
        assert(fgets(line, sizeof line, file));
    } while (line[0] == '#');
    assert(strlen(line) == WIRE_BYTES * 2 + 1);
    for (size_t i = 0; i < WIRE_BYTES; ++i) {
        int high = hex_digit(line[i * 2]);
        int low = hex_digit(line[i * 2 + 1]);
        assert(high >= 0 && low >= 0);
        wire[i] = (uint8_t)((high << 4) | low);
    }
    assert(line[WIRE_BYTES * 2] == '\n');
    assert(fclose(file) == 0);
}

static bool fail_final(void *context, uint8_t digest[32]) {
    (void)context;
    memset(digest, 0xa5, 32);
    return false;
}

static void capture_verified_output(const uint8_t wire[WIRE_BYTES],
    zcl_tx_shielded_output_capture *output) {
    static const uint8_t expected_digest[32] = {
        0xd4,0x96,0x7a,0x82,0x69,0x00,0x77,0x09,
        0xfd,0x06,0x3a,0x59,0x2f,0x73,0x59,0xb8,
        0x64,0xfa,0x39,0x0c,0x76,0xf4,0x60,0x9d,
        0xc9,0xf9,0xb9,0x60,0x69,0xc2,0x7c,0x8b
    };
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    zcl_tx_shielded_replay replay;
    assert(zcl_tx_shielded_replay_begin_output(&replay, WIRE_BYTES,
        0x76b809bbu, &hasher, 0, output));
    for (unsigned pass = 1; pass <= 6; ++pass) {
        for (size_t offset = 0; offset < WIRE_BYTES; offset += 220) {
            size_t take = WIRE_BYTES - offset < 220 ?
                WIRE_BYTES - offset : 220;
            assert(zcl_tx_shielded_replay_feed(&replay,
                wire + offset, take));
        }
        if (pass < 6) assert(zcl_tx_shielded_replay_next(&replay));
    }
    zcl_tx_shielded_facts facts;
    uint8_t digest[32];
    assert(zcl_tx_shielded_replay_finish(&replay, &facts, digest));
    assert(facts.sapling_outputs == 1);
    assert(memcmp(digest, expected_digest, sizeof digest) == 0);
    zcl_tx_shielded_replay_abort(&replay);
}

static void check_note_ciphertext(void) {
    const uint8_t nonce[12] = {0};
    uint8_t key[32], plain[BLUE_SAPLING_NOTE_PLAIN_BYTES];
    uint8_t cipher[BLUE_SAPLING_NOTE_CIPHER_BYTES];
    uint8_t recovered[BLUE_SAPLING_NOTE_PLAIN_BYTES];
    uint8_t core_recovered[BLUE_SAPLING_NOTE_PLAIN_BYTES];
    for (size_t i = 0; i < sizeof key; ++i) key[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof plain; ++i)
        plain[i] = (uint8_t)(i * 73u + 11u);
    uint8_t zero[BLUE_SAPLING_NOTE_PLAIN_BYTES] = {0};
    uint8_t stream[BLUE_SAPLING_NOTE_PLAIN_BYTES];
    uint8_t zero_cipher[BLUE_SAPLING_NOTE_CIPHER_BYTES];
    assert(chacha20_encrypt(key, 1, nonce, zero, sizeof zero, stream));
    assert(chacha20poly1305_encrypt(stream, sizeof stream, NULL, 0,
        nonce, key, zero_cipher));
    assert(memcmp(zero_cipher, zero, sizeof zero) == 0);
    static const uint8_t tag[16] = {
        0x95,0x22,0xd6,0x67,0x36,0x7b,0x4c,0x44,
        0x02,0xb1,0x2d,0x0b,0x07,0x3e,0x21,0x53
    };
    assert(memcmp(zero_cipher + sizeof zero, tag, sizeof tag) == 0);
    assert(blue_sapling_note_open(recovered, key, zero_cipher));
    assert(memcmp(recovered, stream, sizeof stream) == 0);
    assert(chacha20poly1305_encrypt(plain, sizeof plain, NULL, 0,
        nonce, key, cipher));
    assert(blue_sapling_note_open(recovered, key, cipher));
    assert(chacha20poly1305_decrypt(cipher, sizeof cipher, NULL, 0,
        nonce, key, core_recovered));
    assert(memcmp(recovered, plain, sizeof plain) == 0);
    assert(memcmp(recovered, core_recovered, sizeof recovered) == 0);
    uint8_t inplace[BLUE_SAPLING_NOTE_CIPHER_BYTES];
    memcpy(inplace, cipher, sizeof inplace);
    assert(blue_sapling_note_open_inplace(inplace, key));
    assert(memcmp(inplace, plain, sizeof plain) == 0);
    for (size_t i = sizeof plain; i < sizeof inplace; ++i)
        assert(inplace[i] == 0);
    memcpy(inplace, cipher, sizeof inplace);
    assert(!blue_sapling_note_open_inplace(inplace, inplace + 1));
    assert(memcmp(inplace, cipher, sizeof inplace) == 0);
    inplace[sizeof inplace - 1] ^= 1u;
    assert(!blue_sapling_note_open_inplace(inplace, key));
    for (size_t i = 0; i < sizeof inplace; ++i) assert(inplace[i] == 0);
    memcpy(inplace, cipher, sizeof inplace);
    assert(!blue_sapling_note_open_inplace(inplace, NULL));
    for (size_t i = 0; i < sizeof inplace; ++i) assert(inplace[i] == 0);
    uint8_t alias[BLUE_SAPLING_NOTE_CIPHER_BYTES + 1];
    memcpy(alias, cipher, sizeof cipher);
    assert(!blue_sapling_note_open(alias, key, alias));
    assert(memcmp(alias, cipher, sizeof cipher) == 0);
    assert(!blue_sapling_note_open(alias + 1, key, alias));
    assert(memcmp(alias, cipher, sizeof cipher) == 0);
    uint8_t key_alias[BLUE_SAPLING_NOTE_PLAIN_BYTES + 32];
    memset(key_alias, 0xa5, sizeof key_alias);
    assert(!blue_sapling_note_open(key_alias, key_alias + 563, cipher));
    for (size_t i = 0; i < sizeof key_alias; ++i)
        assert(key_alias[i] == 0xa5);
    cipher[0] ^= 1u;
    assert(!blue_sapling_note_open(recovered, key, cipher));
    for (size_t i = 0; i < sizeof recovered; ++i) assert(recovered[i] == 0);
    cipher[0] ^= 1u;
    cipher[sizeof cipher - 1] ^= 1u;
    assert(!blue_sapling_note_open(recovered, key, cipher));
    for (size_t i = 0; i < sizeof recovered; ++i) assert(recovered[i] == 0);
    cipher[sizeof cipher - 1] ^= 1u;
    key[0] ^= 1u;
    assert(!blue_sapling_note_open(recovered, key, cipher));
    for (size_t i = 0; i < sizeof recovered; ++i) assert(recovered[i] == 0);
}

/* The fixture's esk is public test data. This does not exercise device keys. */
static void check_fixture_note(const zcl_tx_shielded_output_capture *output,
    const uint8_t outgoing[64], const zcl_zip243_hasher *hasher) {
    blue_jubjub_decode_workspace workspace;
    struct jub_point point, reference, product;
    uint8_t dh[32], expected_dh[32], key[32];
    uint8_t plain[BLUE_SAPLING_NOTE_PLAIN_BYTES];
    uint8_t core_plain[BLUE_SAPLING_NOTE_PLAIN_BYTES];
    assert(blue_jubjub_decode_public(&point, &workspace, outgoing));
    assert(jub_from_bytes(&reference, outgoing));
    jub_mul_by_cofactor(&reference, &reference);
    for (unsigned i = 0; i < 3; ++i) blue_jub_double(&point, &point);
    assert(blue_jubjub_scalar_mul_lowmem(&product, &point, outgoing + 32));
    assert(blue_jubjub_encode(dh, &product));
    jub_scalar_mul(&product, &reference, outgoing + 32);
    jub_to_bytes(expected_dh, &product);
    assert(memcmp(dh, expected_dh, sizeof dh) == 0);
    assert(blue_sapling_kdf(key, dh, output->epk, hasher));
    assert(blue_sapling_note_open(plain, key, output->enc_ciphertext));
    const uint8_t nonce[12] = {0};
    assert(chacha20poly1305_decrypt(output->enc_ciphertext,
        BLUE_SAPLING_NOTE_CIPHER_BYTES, NULL, 0, nonce, key, core_plain));
    assert(memcmp(plain, core_plain, sizeof plain) == 0);
    uint8_t inplace[BLUE_SAPLING_NOTE_CIPHER_BYTES];
    memcpy(inplace, output->enc_ciphertext, sizeof inplace);
    assert(blue_sapling_note_open_inplace(inplace, key));
    assert(memcmp(inplace, plain, sizeof plain) == 0);
    for (size_t i = sizeof plain; i < sizeof inplace; ++i)
        assert(inplace[i] == 0);
    assert(plain[0] == 0x01);
    static const uint8_t expected_diversifier[11] = {
        0x9c,0xf4,0x94,0x19,0x06,0xe9,0xf1,0x95,
        0x1a,0x91,0x99
    };
    static const uint8_t expected_value[8] = {
        0xf0,0xb9,0xf5,0x05,0x00,0x00,0x00,0x00
    };
    assert(memcmp(plain + 1, expected_diversifier, 11) == 0);
    assert(memcmp(plain + 12, expected_value, 8) == 0);
    blue_sapling_epk_workspace epk_workspace;
    assert(blue_sapling_epk_matches(plain + 1, outgoing + 32,
        output->epk, &epk_workspace));
    uint8_t changed_diversifier[11];
    memcpy(changed_diversifier, plain + 1, sizeof changed_diversifier);
    changed_diversifier[0] ^= 1u;
    assert(!blue_sapling_epk_matches(changed_diversifier,
        outgoing + 32, output->epk, &epk_workspace));
    uint8_t changed_esk[32];
    memcpy(changed_esk, outgoing + 32, sizeof changed_esk);
    changed_esk[0] ^= 1u;
    assert(!blue_sapling_epk_matches(plain + 1,
        changed_esk, output->epk, &epk_workspace));
    memset(&epk_workspace, 0xa5, sizeof epk_workspace);
    assert(!blue_sapling_epk_matches(plain + 1, outgoing + 32,
        (uint8_t *)&epk_workspace, &epk_workspace));
    assert(((uint8_t *)&epk_workspace)[0] == 0xa5);
    assert(!blue_sapling_epk_matches(NULL, outgoing + 32,
        output->epk, &epk_workspace));
    for (size_t i = 0; i < sizeof epk_workspace; ++i)
        assert(((uint8_t *)&epk_workspace)[i] == 0);
    blue_sapling_cm_workspace cm_workspace;
    assert(blue_sapling_cm_matches(plain, outgoing,
        output->cm, &cm_workspace));
    uint8_t changed_cm[32];
    memcpy(changed_cm, output->cm, sizeof changed_cm);
    changed_cm[0] ^= 1u;
    assert(!blue_sapling_cm_matches(plain, outgoing,
        changed_cm, &cm_workspace));
    plain[52] ^= 1u;
    assert(blue_sapling_cm_matches(plain, outgoing,
        output->cm, &cm_workspace));
    plain[52] ^= 1u;
    plain[12] ^= 1u;
    assert(!blue_sapling_cm_matches(plain, outgoing,
        output->cm, &cm_workspace));
    plain[12] ^= 1u;
    uint8_t changed_pk_d[32];
    memcpy(changed_pk_d, outgoing, sizeof changed_pk_d);
    changed_pk_d[0] ^= 1u;
    assert(!blue_sapling_cm_matches(plain, changed_pk_d,
        output->cm, &cm_workspace));
    plain[1] ^= 1u;
    assert(!blue_sapling_cm_matches(plain, outgoing,
        output->cm, &cm_workspace));
    plain[1] ^= 1u;
    plain[20] ^= 1u;
    assert(!blue_sapling_cm_matches(plain, outgoing,
        output->cm, &cm_workspace));
    plain[20] ^= 1u;
    plain[0] = 2;
    assert(!blue_sapling_cm_matches(plain, outgoing,
        output->cm, &cm_workspace));
    plain[0] = 1;
    memset(plain + 20, 0xff, 32);
    assert(!blue_sapling_cm_matches(plain, outgoing,
        output->cm, &cm_workspace));
    memcpy(plain + 20, core_plain + 20, 32);
    memset(&cm_workspace, 0xa5, sizeof cm_workspace);
    assert(!blue_sapling_cm_matches(plain, outgoing,
        (uint8_t *)&cm_workspace, &cm_workspace));
    assert(((uint8_t *)&cm_workspace)[0] == 0xa5);
    assert(!blue_sapling_cm_matches(NULL, outgoing,
        output->cm, &cm_workspace));
    for (size_t i = 0; i < sizeof cm_workspace; ++i)
        assert(((uint8_t *)&cm_workspace)[i] == 0);
    blue_sapling_memo_info memo;
    assert(blue_sapling_memo_inspect(plain + 52, &memo));
    assert(plain[52] == 0xf6 && memo.kind == BLUE_SAPLING_MEMO_FUTURE);
    uint8_t changed_epk[32];
    memcpy(changed_epk, output->epk, sizeof changed_epk);
    changed_epk[0] ^= 1u;
    assert(blue_sapling_kdf(key, dh, changed_epk, hasher));
    assert(!blue_sapling_note_open(plain, key, output->enc_ciphertext));
    for (size_t i = 0; i < sizeof plain; ++i) assert(plain[i] == 0);
    memory_cleanse(&point, sizeof point);
    memory_cleanse(&reference, sizeof reference);
    memory_cleanse(&product, sizeof product);
    memory_cleanse(dh, sizeof dh);
    memory_cleanse(expected_dh, sizeof expected_dh);
    memory_cleanse(key, sizeof key);
    memory_cleanse(plain, sizeof plain);
    memory_cleanse(core_plain, sizeof core_plain);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    check_note_ciphertext();
    static const uint8_t ovk[32] = {
        0xce,0x03,0x88,0x0a,0x87,0x50,0x48,0xf6,
        0x17,0x8e,0xbd,0x84,0x2e,0xdb,0xcb,0xd2,
        0x26,0xee,0x7f,0xe5,0x48,0x9d,0x64,0x8a,
        0xec,0x56,0xea,0x8f,0xba,0xf5,0x0f,0x17
    };
    static const uint8_t expected[32] = {
        0xd9,0x53,0x84,0xf8,0x1b,0x92,0xc9,0x07,
        0xc1,0x32,0x79,0x86,0xcb,0x66,0xb7,0x65,
        0x42,0x83,0x73,0x72,0x59,0x5e,0xa0,0x5f,
        0xff,0xec,0x20,0x6d,0x4d,0x44,0x40,0xbb
    };
    uint8_t wire[WIRE_BYTES], key[32];
    read_fixture(argv[1], wire);
    zcl_tx_shielded_output_capture output;
    capture_verified_output(wire, &output);
    assert(memcmp(output.cv, wire + OUTPUT_OFFSET, 32) == 0);
    assert(memcmp(output.enc_ciphertext,
        wire + OUTPUT_OFFSET + 96, 580) == 0);
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    assert(blue_sapling_ock(key, ovk, output.cv, output.cm,
        output.epk, &hasher));
    assert(memcmp(key, expected, sizeof key) == 0);
    uint8_t ovk_alias[33];
    memcpy(ovk_alias, ovk, 32);
    ovk_alias[32] = 0xa5;
    assert(!blue_sapling_ock(ovk_alias + 1, ovk_alias,
        output.cv, output.cm, output.epk, &hasher));
    assert(memcmp(ovk_alias, ovk, 32) == 0 && ovk_alias[32] == 0xa5);
    uint8_t saved_cv[32];
    memcpy(saved_cv, output.cv, sizeof saved_cv);
    assert(!blue_sapling_ock(output.cv, ovk, output.cv,
        output.cm, output.epk, &hasher));
    assert(memcmp(output.cv, saved_cv, sizeof saved_cv) == 0);
    uint8_t outgoing[64];
    const uint8_t *out_ciphertext = output.out_ciphertext;
    assert(blue_sapling_out_open(outgoing, key, out_ciphertext));
    uint8_t out_alias[BLUE_SAPLING_OUT_CIPHER_BYTES + 1];
    memcpy(out_alias, out_ciphertext, BLUE_SAPLING_OUT_CIPHER_BYTES);
    assert(!blue_sapling_out_open(out_alias, key, out_alias));
    assert(memcmp(out_alias, out_ciphertext,
        BLUE_SAPLING_OUT_CIPHER_BYTES) == 0);
    assert(!blue_sapling_out_open(out_alias + 1, key, out_alias));
    assert(memcmp(out_alias, out_ciphertext,
        BLUE_SAPLING_OUT_CIPHER_BYTES) == 0);
    const uint8_t nonce[12] = {0};
    uint8_t core_outgoing[64];
    assert(chacha20poly1305_decrypt(out_ciphertext, 80,
        NULL, 0, nonce, key, core_outgoing));
    assert(memcmp(outgoing, core_outgoing, sizeof outgoing) == 0);
    static const uint8_t expected_outgoing[64] = {
        0x25,0xd4,0xfe,0xd2,0xb7,0xef,0x10,0x5c,
        0xaa,0xe1,0xf6,0x9f,0x11,0x62,0x6d,0x7a,
        0xc7,0x9a,0x51,0xa6,0x9f,0xc2,0x01,0x63,
        0xb4,0x86,0x68,0xd7,0x0f,0xd1,0x0f,0x3a,
        0xca,0xd2,0xf8,0xc7,0x01,0x5b,0xcd,0x97,
        0x59,0x0b,0xf2,0xba,0x2f,0x68,0x30,0x8e,
        0x18,0x6b,0x3d,0x62,0x41,0xa1,0xe8,0x72,
        0x5c,0x21,0x08,0xf3,0x12,0x4b,0xba,0x06
    };
    assert(memcmp(outgoing, expected_outgoing, sizeof outgoing) == 0);
    uint8_t inplace_out[BLUE_SAPLING_OUT_CIPHER_BYTES];
    memcpy(inplace_out, out_ciphertext, sizeof inplace_out);
    assert(blue_sapling_out_open_inplace(inplace_out, key));
    assert(memcmp(inplace_out, outgoing, sizeof outgoing) == 0);
    for (size_t i = sizeof outgoing; i < sizeof inplace_out; ++i)
        assert(inplace_out[i] == 0);
    memcpy(inplace_out, out_ciphertext, sizeof inplace_out);
    assert(!blue_sapling_out_open_inplace(inplace_out, inplace_out + 1));
    assert(memcmp(inplace_out, out_ciphertext, sizeof inplace_out) == 0);
    inplace_out[79] ^= 1u;
    assert(!blue_sapling_out_open_inplace(inplace_out, key));
    for (size_t i = 0; i < sizeof inplace_out; ++i)
        assert(inplace_out[i] == 0);
    check_fixture_note(&output, outgoing, &hasher);
    uint8_t altered_ciphertext[80];
    memcpy(altered_ciphertext, out_ciphertext, sizeof altered_ciphertext);
    altered_ciphertext[79] ^= 1u;
    assert(!blue_sapling_out_open(outgoing, key, altered_ciphertext));
    for (unsigned i = 0; i < sizeof outgoing; ++i)
        assert(outgoing[i] == 0);
    uint8_t wrong_key[32];
    memcpy(wrong_key, key, sizeof wrong_key);
    wrong_key[0] ^= 1u;
    assert(!blue_sapling_out_open(outgoing, wrong_key, out_ciphertext));
    for (unsigned i = 0; i < sizeof outgoing; ++i)
        assert(outgoing[i] == 0);
    memcpy(altered_ciphertext, out_ciphertext, sizeof altered_ciphertext);
    altered_ciphertext[7] ^= 1u;
    assert(!blue_sapling_out_open(outgoing, key, altered_ciphertext));
    for (unsigned i = 0; i < sizeof outgoing; ++i)
        assert(outgoing[i] == 0);
    uint8_t changed_cv[32];
    memcpy(changed_cv, output.cv, sizeof changed_cv);
    changed_cv[0] ^= 1u;
    assert(blue_sapling_ock(key, ovk, changed_cv, output.cm,
        output.epk, &hasher));
    assert(memcmp(key, expected, sizeof key) != 0);
    hasher.final = fail_final;
    assert(!blue_sapling_ock(key, ovk, output.cv, output.cm,
        output.epk, &hasher));
    for (unsigned i = 0; i < sizeof key; ++i) assert(key[i] == 0);
    assert(!blue_sapling_ock(key, ovk, output.cv, output.cm,
        output.epk, NULL));
    for (unsigned i = 0; i < sizeof key; ++i) assert(key[i] == 0);
    memset(&context, 0, sizeof context);
    puts("Blue Sapling outgoing key: passed");
    return 0;
}
