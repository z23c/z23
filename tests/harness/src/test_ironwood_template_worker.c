/* purpose: Check exact private template solving and unsupported input refusal. */
/* H216 public template, SHA256 2a25d673b08163dd4f2cba77e4afb7f4aaff9b00c23ae76415154ce6bd93b734. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "test/test_core.h"
#include "base/hex.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "core/serialize.h"
#include "domain/consensus/equihash.h"
#include "json/json.h"
#include "primitives/block.h"
#include "util/spawn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool read_fixture(char *text, size_t cap)
{
    FILE *f = fopen("tests/fixtures/ironwood/gbt-coinbase-template.json", "rb");
    if (!f) return false;
    size_t n = fread(text, 1, cap - 1, f);
    bool ok = !ferror(f) && feof(f);
    if (fclose(f)) ok = false;
    text[n] = '\0';
    return ok;
}

static int run_worker(const char *path, char *output, size_t cap)
{
    if (!output || cap < 2) return -1;
    output[0] = '\0';
    const char *const argv[] = {"build/bin/z23_ironwood_template_worker", path, NULL};
    struct zcl_spawn_binary_observation obs = {0};
    struct zcl_result result = zcl_spawn_capture_binary(argv, output, cap - 1, 120000, &obs);
    if (!obs.exit_observed || obs.timed_out || obs.overflow || !obs.eof || obs.output_len >= cap) return -1;
    size_t n = obs.output_len;
    if (n && output[n - 1] == '\n') --n;
    output[n] = '\0';
    if (result.ok && obs.exit_code == 0) return 0;
    return obs.exit_code == 1 ? 1 : -1;
}

static bool check_block(const char *hex, const char *fixture)
{
    size_t n = strcspn(hex, "\n");
    if (!n || n % 2 || n > 8192) return false;
    uint8_t bytes[4096];
    if (!zcl_hex_decode(hex, bytes, n / 2)) return false;
    struct byte_stream s;
    stream_init_from_data(&s, bytes, n / 2);
    struct block b = {0};
    bool ok = block_deserialize(&b, &s) && !s.error && !stream_remaining(&s) && b.num_vtx == 1;
    struct json_value root = {0};
    if (ok) ok = json_read(&root, fixture, strlen(fixture));
    const struct json_value *obj = json_get(&root, "result");
    const char *expected = json_get_str(json_get(json_get(obj, "coinbasetxn"), "data"));
    struct byte_stream tx;
    stream_init(&tx, 256);
    uint8_t raw[2048];
    size_t expected_len = expected ? strlen(expected) : 0;
    if (ok) ok = expected_len && expected_len % 2 == 0 && expected_len <= sizeof raw * 2 &&
        zcl_hex_decode(expected, raw, expected_len / 2) && transaction_serialize(&b.vtx[0], &tx) &&
        tx.size == expected_len / 2 && !memcmp(tx.data, raw, tx.size);
    struct uint256 root_hash, prev, block_hash;
    if (ok) ok = transaction_hash_serialized(&b.vtx[0], &root_hash) &&
        uint256_eq(&root_hash, &b.header.hashMerkleRoot);
    uint256_set_hex(&prev, "004a13de2db21655e8ae14b60261046de5eef4e5daca9f80c6532f2079df71a5");
    if (ok) ok = uint256_eq(&prev, &b.header.hashPrevBlock) &&
        chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD);
    bool equihash = false;
    if (ok) {
        block_header_get_hash(&b.header, &block_hash);
        ok = domain_consensus_verify_equihash_solution(&b.header, &chain_params_get()->consensus, &equihash).ok &&
             equihash && CheckProofOfWork(block_hash, b.header.nBits, &chain_params_get()->consensus);
    }
    chain_params_select(CHAIN_MAIN);
    stream_free(&tx); json_free(&root); block_free(&b);
    return ok;
}

static bool reject_mutation(const char *text, const char *needle, const char *replacement,
                            const char *path)
{
    const char *p = strstr(text, needle);
    if (!p) return false;
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(text, 1, (size_t)(p - text), f) == (size_t)(p - text) &&
        fputs(replacement, f) >= 0 && fputs(p + strlen(needle), f) >= 0;
    if (fclose(f)) ok = false;
    char output[8192];
    if (ok) ok = run_worker(path, output, sizeof output) == 1 && output[0] == '\0';
    return ok;
}

int test_ironwood_template_worker(void)
{
    char fixture[4096], output[8192], dir[512], path[600];
    bool ok = read_fixture(fixture, sizeof fixture) &&
        run_worker("tests/fixtures/ironwood/gbt-coinbase-template.json", output, sizeof output) == 0 &&
        check_block(output, fixture) && test_mkdtemp(dir, sizeof dir, "ironwood_gbt");
    if (ok) {
        snprintf(path, sizeof path, "%s/with'quote.json", dir);
        ok = reject_mutation(fixture, "\"transactions\":[]", "\"transactions\":[{}]", path) &&
             reject_mutation(fixture, "\"version\":4", "\"version\":5", path) &&
             reject_mutation(fixture, "200f0f0f", "200f0f0g", path) &&
             reject_mutation(fixture, "\"height\":216", "\"height\":0", path);
        remove(path);
        test_cleanup_tmpdir(dir);
    }
    if (!ok) fprintf(stderr, "Ironwood template worker fixture failed\n");
    return ok ? 0 : 1;
}
