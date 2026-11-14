/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_CONSENSUS_STATE_CHECKPOINT_REAL_TEST_H
#define ZCL_CONSENSUS_STATE_CHECKPOINT_REAL_TEST_H

#include "base/hex.h"
#include "test/rom_checkpoint_resume.h"
#include "conditions/checkpoint_header_solution_repair.h"
#include "services/block_index_loader.h"
#include "storage/coins_kv.h"

void validate_headers_ensure_set_validator_for_test(vh_validator_fn fn, void *user);

static bool csi_checkpoint_block(const char *path, struct block *block)
{
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char hex[16384];
    bool ok = fgets(hex, sizeof(hex), f) != NULL && fgetc(f) == EOF && !ferror(f);
    if (fclose(f)) ok = false;
    if (!ok) return false;
    hex[strcspn(hex, "\r\n")] = 0;
    uint8_t bytes[8192]; size_t n = 0;
    if (!zcl_hex_decode_n(hex, bytes, sizeof(bytes), &n)) return false;
    struct byte_stream s;
    stream_init_from_data(&s, bytes, n);
    block_init(block);
    ok = block_deserialize(block, &s);
    stream_free(&s);
    if (!ok) block_free(block);
    return ok;
}

/* The flat-index trailer provides only a hash-bound header. A zero-tx block
 * is a serialization carrier for this fixture, not a consensus-valid block. */
static bool csi_checkpoint_header_carrier(const struct block_header *hdr,
                                          struct block_header *out)
{
    struct block carrier, decoded;
    block_init(&carrier); carrier.header = *hdr;
    struct byte_stream bytes; stream_init(&bytes, 1024);
    bool ok = block_serialize(&carrier, &bytes);
    struct byte_stream input; stream_init_from_data(&input, bytes.data, bytes.size);
    block_init(&decoded);
    ok = ok && block_deserialize(&decoded, &input) && decoded.num_vtx == 0 &&
         stream_remaining(&input) == 0;
    if (ok) *out = decoded.header;
    block_free(&decoded); stream_free(&input); stream_free(&bytes);
    return ok;
}

static bool csi_checkpoint_header_from_index(struct main_state *ms,
                                              struct block_header *out)
{
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    struct uint256 expected, actual;
    if (!cp || cp->height != 3056758) return false;
    memcpy(expected.data, cp->block_hash, sizeof(expected.data));
    struct block_index *bi = block_map_find(&ms->map_block_index, &expected);
    size_t len = 0;
    const unsigned char *solution = bi ? block_index_solution(bi, &len) : NULL;
    if (!bi || bi->nHeight != cp->height || !bi->phashBlock || !bi->pprev ||
        !bi->pprev->phashBlock || !solution || len == 0 || len > MAX_SOLUTION_SIZE)
        return false;
    struct block_header hdr; block_header_init(&hdr);
    hdr.nVersion = bi->nVersion; hdr.hashPrevBlock = *bi->pprev->phashBlock;
    hdr.hashMerkleRoot = block_index_merkle_root(bi);
    hdr.hashFinalSaplingRoot = bi->hashFinalSaplingRoot;
    hdr.nTime = bi->nTime; hdr.nBits = bi->nBits; hdr.nNonce = block_index_nonce(bi);
    memcpy(hdr.nSolution, solution, len); hdr.nSolutionSize = len;
    block_header_get_hash(&hdr, &actual);
    return uint256_eq(&actual, &expected) && csi_checkpoint_header_carrier(&hdr, out);
}

static bool csi_checkpoint_header(const char *index_dir, const char *raw,
                                  struct block_header *out)
{
    if (raw) {
        struct block block;
        if (!csi_checkpoint_block(raw, &block)) return false;
        *out = block.header; block_free(&block);
        return true;
    }
    const char *fallback = getenv("ZCL_TEST_CHECKPOINT_INDEX_HEADER");
    if (!fallback || strcmp(fallback, "1") != 0) return false;
    chain_params_select(CHAIN_MAIN);
    struct main_state ms; main_state_init(&ms);
    bool ok = load_block_index_flat(index_dir, &ms).ok &&
              csi_checkpoint_header_from_index(&ms, out);
    main_state_free(&ms); return ok;
}


static bool csi_checkpoint_seed(const char *dir, const struct block_header *header, bool positive)
{
    chain_params_select(CHAIN_MAIN);
    checkpoint_header_solution_set_frozen_verifier_for_test(NULL);
    validate_headers_ensure_set_validator_for_test(NULL, NULL);
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp || cp->height != 3056758 || !header) return false;
    struct uint256 expected, actual;
    memcpy(expected.data, cp->block_hash, sizeof(expected.data));
    block_header_get_hash(header, &actual);
    struct main_state ms; main_state_init(&ms);
    bool ok = uint256_eq(&actual, &expected) &&
        (!positive || load_block_index_flat(dir, &ms).ok) &&
        progress_store_open(dir);
    struct consensus_state_install_stamp stamp; bool found = true;
    if (ok) {
        struct block_header wrong = *header;
        wrong.nNonce.data[0] ^= 1;
        ok = !checkpoint_header_solution_verify_and_persist(&ms, cp->height, &expected, &wrong) &&
            consensus_state_install_read_authority_stamp(progress_store_db(), &stamp, &found) && !found;
        if (ok && positive) ok = checkpoint_header_solution_verify_and_persist(&ms, cp->height, &expected, header) &&
            validate_headers_stage_has_pass_record(cp->height, &expected);
    }
    progress_store_close(); main_state_free(&ms);
    return ok;
}

static bool csi_checkpoint_wait(pid_t child, int *status)
{
    for (int i = 0; i < 600; ++i) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) return true;
        if (result < 0 && errno == ECHILD) return false;
        if (result < 0 && errno != EINTR) break;
        struct timespec delay = {.tv_sec = 1};
        (void)nanosleep(&delay, NULL);
    }
    if (kill(child, SIGKILL) != 0 && errno == ESRCH) return false;
    while (waitpid(child, status, 0) < 0 && errno == EINTR) {}
    return false;
}

static bool csi_checkpoint_report(const char *log, bool positive, bool waited, int status)
{
    FILE *f = fopen(log, "r");
    bool banner = false, header_refusal = false; char line[4096];
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, positive ? "INSTALLED: -install-consensus-bundle:" :
                                        "REFUSED: -install-consensus-bundle:")) banner = true;
            if (strstr(line, "checkpoint bundle deferred: validated header chain has not yet"))
                header_refusal = true;
        }
        if (ferror(f)) banner = false;
        if (fclose(f)) banner = false;
    }
    return waited && WIFEXITED(status) && banner &&
        (positive ? WEXITSTATUS(status) == 0 :
                    WEXITSTATUS(status) != 0 && header_refusal);
}

static bool csi_checkpoint_install(const char *dir, const char *bundle, const char *params, bool positive)
{
    char data_arg[PATH_MAX + 32], bundle_arg[PATH_MAX + 64], params_arg[PATH_MAX + 32];
    int a = snprintf(data_arg, sizeof(data_arg), "-datadir=%s", dir);
    int b = snprintf(bundle_arg, sizeof(bundle_arg), "-install-consensus-bundle=%s", bundle);
    int c = snprintf(params_arg, sizeof(params_arg), "-paramsdir=%s", params);
    if (a < 0 || b < 0 || c < 0 || (size_t)a >= sizeof(data_arg) ||
        (size_t)b >= sizeof(bundle_arg) || (size_t)c >= sizeof(params_arg)) return false;
    char log[PATH_MAX];
    if (!csi_real_path(log, sizeof(log), dir, "installer.log")) return false;
    uint64_t parent = (uint64_t)getpid();
    pid_t child = fork();
    if (child == 0) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(126);
        int fd = open(log, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0 || dup2(fd, STDERR_FILENO) < 0) _exit(126);
        close(fd);
        unsetenv("ZCL_DEPLOY_ALLOW_CANONICAL");
        execl("build/bin/z23-dev", "z23-dev", data_arg, bundle_arg, params_arg,
              "-operator-lane=dev", "-nolegacyimport", "-nolegacyutxoimport",
              "-no-tor", "-private-listeners", "-observation=0",
              "-connect=127.0.0.1:1", "-port=28033", "-rpcport=28232",
              "-httpsport=28443", "-fsport=28034", (char *)NULL);
        _exit(127);
    }
    int status = 0;
    bool waited = child > 0 && csi_checkpoint_wait(child, &status);
    return csi_checkpoint_report(log, positive, waited, status);
}

static bool csi_checkpoint_stamp(const char *dir)
{
    if (!progress_store_open(dir)) return false;
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    struct consensus_state_install_stamp stamp; bool found = false; uint64_t generation = 0;
    bool ok = cp && consensus_state_install_read_authority_stamp(progress_store_db(), &stamp, &found) &&
        found && stamp.kind == CONSENSUS_INSTALL_STAMP_CHECKPOINT_ROM && stamp.height == cp->height &&
        !memcmp(stamp.block_hash, cp->block_hash, 32) &&
        !memcmp(stamp.utxo_root, cp->sha3_hash, 32) &&
        coins_kv_get_authority_generation(progress_store_db(), &generation) &&
        generation != 0 && generation == stamp.coins_generation;
    progress_store_close(); return ok;
}

static bool csi_checkpoint_digest(const char *path, const char *expected_hex)
{
    uint8_t expected[32], digest[32], buf[65536];
    if (!zcl_hex_decode(expected_hex, expected, sizeof(expected))) return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st; bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
    struct sha256_ctx hash; sha256_init(&hash);
    while (ok) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n == 0) break;
        if (n < 0) { if (errno == EINTR) continue; ok = false; break; }
        sha256_write(&hash, buf, (size_t)n);
    }
    if (close(fd)) ok = false;
    sha256_finalize(&hash, digest);
    return ok && !memcmp(digest, expected, sizeof(digest));
}

static bool csi_checkpoint_absent(const char *dir)
{
    if (!progress_store_open(dir)) return false;
    struct consensus_state_install_stamp stamp; bool found = true;
    bool ok = consensus_state_install_read_authority_stamp(progress_store_db(), &stamp, &found) && !found;
    progress_store_close(); return ok;
}

struct csi_checkpoint_paths {
    const char *scratch, *index, *raw, *bundle, *params;
    char root[PATH_MAX], good[PATH_MAX], bad[PATH_MAX];
    char good_index[PATH_MAX], copy[PATH_MAX];
};

static bool csi_checkpoint_inputs(struct csi_checkpoint_paths *p)
{
    p->scratch = getenv("ZCL_TEST_CHECKPOINT_SCRATCH");
    p->index = getenv("ZCL_TEST_CHECKPOINT_INDEX");
    p->raw = getenv("ZCL_TEST_CHECKPOINT_BLOCK");
    p->bundle = getenv("ZCL_TEST_CHECKPOINT_BUNDLE");
    p->params = getenv("ZCL_TEST_CHECKPOINT_PARAMS");
    if (!p->scratch || !p->index || !p->bundle || !p->params) return false;
    struct stat st;
    return lstat(p->scratch, &st) == 0 && S_ISDIR(st.st_mode) &&
        st.st_uid == geteuid() && !(st.st_mode & 077);
}

static bool csi_checkpoint_paths_init(struct csi_checkpoint_paths *p)
{
    if (!csi_checkpoint_inputs(p)) return false;
    if (!csi_real_path(p->root, sizeof(p->root), p->scratch, "checkpoint-install-XXXXXX") || !mkdtemp(p->root)) return false;
    if (!csi_real_path(p->good, sizeof(p->good), p->root, "good") ||
        !csi_real_path(p->bad, sizeof(p->bad), p->root, "bad")) return false;
    if (mkdir(p->good, 0700) || mkdir(p->bad, 0700)) return false;
    return csi_real_path(p->good_index, sizeof(p->good_index), p->good, "block_index.bin") &&
        csi_real_path(p->copy, sizeof(p->copy), p->root, "bundle.sqlite");
}

static bool csi_checkpoint_copy_inputs(struct csi_checkpoint_paths *p)
{
    const char *bundle_sha = "6bc3bf5152e5cd38deadc344d563478696d3800f4417e564119319196447ae83";
    const char *index_sha = "68cda2bf810cc1583be5258816a3852948e625f99e2108e3b6bb104a41f733da";
    if (!csi_checkpoint_digest(p->bundle, bundle_sha) || !csi_checkpoint_digest(p->index, index_sha)) return false;
    if (!csi_real_copy(p->index, p->good_index)) return false;
    const char *resume = getenv("ZCL_TEST_CHECKPOINT_ROM_RESUME");
    if (resume) {
        if (strcmp(resume, "1") != 0 ||
            !test_rom_checkpoint_resume(p->bundle, p->root, p->copy, sizeof(p->copy))) return false;
    } else if (!csi_real_copy(p->bundle, p->copy)) return false;
    if (!csi_checkpoint_digest(p->bundle, bundle_sha) || !csi_checkpoint_digest(p->copy, bundle_sha)) return false;
    if (!csi_checkpoint_digest(p->index, index_sha) || !csi_checkpoint_digest(p->good_index, index_sha)) return false;
    return chmod(p->copy, 0400) == 0;
}

static int csi_checkpoint_real(void)
{
    struct csi_checkpoint_paths p = {0};
    if (!csi_checkpoint_paths_init(&p)) {
        fputs("checkpoint real fixture: incomplete inputs or unsafe scratch\n", stderr); return 1;
    }
    struct block_header header;
    bool ok = csi_checkpoint_copy_inputs(&p) &&
        csi_checkpoint_header(p.good, p.raw, &header) &&
        csi_checkpoint_seed(p.bad, &header, false) && csi_checkpoint_install(p.bad, p.copy, p.params, false) &&
        csi_checkpoint_absent(p.bad) && csi_checkpoint_seed(p.good, &header, true) &&
        csi_checkpoint_install(p.good, p.copy, p.params, true) && csi_checkpoint_stamp(p.good);
    fprintf(stderr, "checkpoint real fixture: %s; retained %s\n", ok ? "PASS" : "FAIL", p.root);
    return ok ? 0 : 1;
}
#endif
