<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Wallet scan identity snapshots

On 2026-11-07, a synthetic benchmark compared baseline commit
`950247c617767918d5a93022aa6dbd8f1e875da0` with the scan-snapshot patch
(SHA-256 `283bb64c01783111f2e6b7dcf0ad1a1531c43a55c8e16095b7e9065168df4b2d`).
The host was an AMD Ryzen 9 7950X3D, using GCC 14.2.0. Runs used the
registered node database catchup test and the production strict Sapling replay
path. Each replay covered 256 authenticated synthetic blocks and 20 synthetic
incoming viewing keys. Wall and process CPU measurements cover replay only;
fixture construction is excluded.

For sparse input, one block contained an encrypted wallet output. The two
baseline-first pairs produced these times in milliseconds:

| Pair | Version | First wall / CPU | Retry walls | Retry CPUs |
| --- | --- | --- | --- | --- |
| 1 | Baseline | 29.42 / 30.59 | 28.12, 28.81, 27.28 | 29.28, 29.96, 28.31 |
| 1 | Snapshot | 24.62 / 24.50 | 24.28, 23.29, 21.34 | 25.26, 24.33, 22.32 |
| 2 | Baseline | 25.99 / 27.00 | 26.86, 26.52, 27.52 | 27.99, 27.57, 28.51 |
| 2 | Snapshot | 16.78 / 17.58 | 16.89, 16.55, 17.33 | 17.56, 17.26, 18.12 |

The serialized block file SHA3-256 was
`a415cf3e2db639e1aa063013a3134adc60ff588725a609cfe0dc4e117eb77c92`
and scan identity was
`013d2b26da31ff3c4505d461f2e9db8a3088ac7448f6892233b33b4dbd687bdb`
in all four runs. Each run checked successful replay and the note and
projection count and value. The sparse benchmark driver SHA-256 was
`9813e47b30fea26e0efc79eeae7facf2b0a22919df25a41ebe73b694bfe3b901`.

A separate decrypt-heavy fixture contained 255 encrypted wallet outputs in
256 blocks. Baseline first replay was 1056.88 ms wall and 1057.79 ms CPU;
snapshot first replay was 1080.09 ms wall and 1078.89 ms CPU. Baseline
retry wall times were 1074.42, 1038.01 and 1034.73 ms; snapshot retry wall
times were 1052.01, 1042.04 and 1072.09 ms. The serialized input and scan
identity matched between versions. This fixture showed no meaningful replay
improvement. Its driver SHA-256 was
`a28b33f1f38a5342660752b173f634458729c147077970435f7edc950815cd28`.

An independent synthetic API microbenchmark with 20 keys measured the prior
identity hash at 6680–6716 ns, the refactored hash at 6782–6873 ns, snapshot
matching at 576–578 ns, and capture plus free at 6981–7001 ns per operation.
These timings describe the API, not end-to-end replay.

Both sparse pairs ran baseline before snapshot, on a shared host. Order and
host load limit causal attribution; the fixtures do not establish Android
latency or whole-chain speed. The registered wallet and node database catchup
groups passed together, two of two with no skips. Flat-test cleanup warnings
also occurred on the unmodified baseline.

## Reproduction

Apply the dense benchmark diff below to the baseline, then run the registered
group with `devbuild --wait --project z23 --class normal make -j4
 t-fast-exact ONLY=node_db_catchup_service`. Reverse the benchmark diff,
apply the candidate patch, reapply the benchmark diff and run the same group.
For the sparse workload, additionally apply the sparse delta below to the
instrumented test source. Reverse both benchmark diffs before retaining the
candidate. The second sparse pair repeated baseline then candidate. Capture
standard output and standard error for each run; preserve first and retry
measurements separately. The benchmark additions are experimental and must not
be included in the production candidate.

The dense baseline and candidate log SHA-256 values were respectively
`6c9a445544f0d11db21b9e41212a103c7a37acf1cb9698cc2156ca7ecc9332bc` and
`5af0a2b79fc21b343fa1ee427796886a55d142c587fff4cbecd5c3a374314642`.
Sparse pair 1 log hashes were
`1c866d6f4600f322e808f96059d578550220e461cbc6ce27ecf92aab07fe3880` and
`8017896b2b4b64f008096e90b517062a11232a5b1b885379a3b8c622c80ed540`;
pair 2 were
`eb68eb244f8effac7aedf47159dd5003cb02ee159f0834700147bd2d7ddcf5aa` and
`c9bb628e908a04309c627fae56139b27ae523af52ba7fdec80e6311b1c35feb6`.

In the dense diff, replace the single line `␠` with one ASCII space before applying.

Dense benchmark diff:

```diff
--- a/tests/harness/src/test_node_db_catchup_service.c
+++ b/tests/harness/src/test_node_db_catchup_service.c
@@ -22,6 +22,8 @@
 #include "sapling/note_encryption.h"
 #include "sapling/sapling.h"
 #include "support/cleanse.h"
+#include <time.h>
+#include "sha3/sha3.h"
 #ifndef _WIN32
 #include <sys/wait.h>
 #endif
@@ -3083,8 +3085,8 @@
     char dir[256], dbpath[320], logpath[320];
     struct wallet *wallet;
     struct main_state state;
-    struct block_index slots[3];
-    struct uint256 hashes[3], root, note_txid, spend_txid;
+    struct block_index slots[257];
+    struct uint256 hashes[257], root, note_txid, spend_txid;
     int height_offset;
     bool fresh_spend;
     struct incremental_merkle_tree tree;
@@ -3130,11 +3132,12 @@
     bool ok = transaction_alloc(tx, 1, 1);
     tx->version = SAPLING_TX_VERSION; tx->overwintered = true;
     tx->version_group_id = SAPLING_VERSION_GROUP_ID;
-    if (height == 1) {
+    if (height == 1 || height >= 3) {
         tx->v_shielded_output = zcl_calloc(2, sizeof(*tx->v_shielded_output), "replay fixture outputs");
         ok = ok && tx->v_shielded_output;
         tx->num_shielded_output = ok ? 2 : 0;
         uint8_t rcm1[32] = {2}, rcm2[32] = {1};
+        if (height >= 3) { rcm1[1] = height; rcm2[1] = height; rcm1[2] = height >> 8; rcm2[2] = height >> 8; }
         if (ok) ok = sapling_compute_cm(d, pk, 9, rcm1, tx->v_shielded_output[0].cm.data) &&
                      ndc_replay_encrypt(f, &tx->v_shielded_output[1], d, pk, rcm2);
         if (ok) {
@@ -3991,6 +3994,114 @@
         ndc_cutover_coordinator(f, svc, db, false);
 }
␠
+static bool ndc_bench_digest_file(const char *dir, uint8_t digest[32])
+{
+    char path[320];
+    int n = snprintf(path, sizeof(path), "%s/blocks/blk00000.dat", dir);
+    if (n < 0 || (size_t)n >= sizeof(path)) return false;
+    FILE *in = fopen(path, "rb");
+    if (!in) return false;
+    struct sha3_256_ctx ctx;
+    sha3_256_init(&ctx);
+    unsigned char buf[4096];
+    size_t count;
+    while ((count = fread(buf, 1, sizeof(buf), in)) != 0) sha3_256_write(&ctx, buf, count);
+    bool ok = !ferror(in);
+    if (fclose(in) != 0) ok = false;
+    if (ok) sha3_256_finalize(&ctx, digest);
+    return ok;
+}
+
+/* Isolated scratch benchmark: real authenticated replay, deterministic input. */
+static bool ndc_bench_range(void)
+{
+    struct ndc_replay_fixture f = {0};
+    test_make_tmpdir(f.dir, sizeof(f.dir), "node_db_catchup", "replay_benchmark");
+    char path[320];
+    snprintf(path, sizeof(path), "%s/blocks", f.dir);
+    bool ok = mkdir(path, 0755) == 0;
+    snprintf(f.dbpath, sizeof(f.dbpath), "%s/node.db", f.dir);
+    snprintf(f.logpath, sizeof(f.logpath), "%s/events.log", f.dir);
+    f.wallet = zcl_calloc(1, sizeof(*f.wallet), "replay benchmark wallet");
+    if (!f.wallet) return false;
+    wallet_init(f.wallet);
+    ok = ok && wallet_readiness_initialize(f.wallet, WALLET_READINESS_PENDING, true, 1);
+    main_state_init(&f.state);
+    sapling_tree_init(&f.tree);
+    uint8_t seed[32] = {1}, d[11], pk[32];
+    ok = ok && sapling_keystore_set_seed(&f.wallet->sapling_keys, seed) &&
+        sapling_keystore_new_address(&f.wallet->sapling_keys, d, pk);
+    for (int h = 1; ok && h <= 256; ++h)
+        ok = ndc_replay_write_fixture_block(&f, h, d, pk);
+    struct sapling_keystore *ks = &f.wallet->sapling_keys;
+    struct sapling_key_entry original = ks->keys[0];
+    for (size_t i = 0; i < 19; ++i) {
+        ks->keys[i] = original;
+        memset(ks->keys[i].ivk, 0, sizeof(ks->keys[i].ivk));
+        ks->keys[i].ivk[0] = (uint8_t)(i + 2);
+        if (!memcmp(ks->keys[i].ivk, original.ivk, 32)) ks->keys[i].ivk[1] = 1;
+    }
+    ks->keys[19] = original;
+    ks->num_keys = 20;
+    event_log_t *log = ok ? event_log_open(f.logpath) : NULL;
+    wallet_projection_set_event_log(log);
+    struct node_db db = {0};
+    bool opened = log && node_db_open(&db, f.dbpath);
+    struct db_service svc;
+    db_service_init(&svc);
+    bool started = opened && db_service_attach(&svc, &db) && db_service_start_test_worker(&svc);
+    struct app_runtime_context runtime = {.db_service = &svc};
+    app_runtime_set_current(&runtime);
+    uint8_t identity[32];
+    ok = started && wallet_scan_identity(f.wallet, identity);
+    snprintf(path, sizeof(path), "%s/projection.db", f.dir);
+    wallet_projection_t *projection = ok ? wallet_projection_open(path, log) : NULL;
+    ok = ok && projection;
+    uint8_t file_digest[32];
+    ok = ok && ndc_bench_digest_file(f.dir, file_digest);
+    if (ok) {
+        fprintf(stderr, "REPLAY_BENCH scan_identity=");
+        for (size_t i = 0; i < 32; ++i) fprintf(stderr, "%02x", identity[i]);
+        fprintf(stderr, " archive_sha3=");
+        for (size_t i = 0; i < 32; ++i) fprintf(stderr, "%02x", file_digest[i]);
+        fprintf(stderr, "\n");
+    }
+    fprintf(stderr, "REPLAY_BENCH endpoint=");
+    for (size_t i = 0; i < 32; ++i) fprintf(stderr, "%02x", f.hashes[256].data[i]);
+    fprintf(stderr, "\n");
+    for (int run = 0; ok && run < 4; ++run) {
+        struct timespec wall0, wall1, cpu0, cpu1;
+        ok = clock_gettime(CLOCK_MONOTONIC, &wall0) == 0 &&
+             clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu0) == 0;
+        struct sapling_replay_result r = node_db_catchup_sapling_replay_at_reference(
+            &svc, &db, &f.state, f.wallet, f.dir, 1, 256, 256, f.hashes[256].data,
+            SAPLING_REPLAY_DISCOVER, f.hashes[256].data, identity, NULL);
+        ok = ok && clock_gettime(CLOCK_MONOTONIC, &wall1) == 0 &&
+             clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu1) == 0 &&
+             r.status == SAPLING_REPLAY_COMPLETE && r.last_complete == 256 &&
+             db_sapling_note_count_unspent(&db) == 255 &&
+             wallet_projection_catch_up(projection) != UINT64_MAX &&
+             wallet_projection_note_count(projection) == 255 &&
+             wallet_projection_total_value_zat(projection) == 2550;
+        if (ok) {
+            long long wall = (wall1.tv_sec - wall0.tv_sec) * 1000000000LL + wall1.tv_nsec - wall0.tv_nsec;
+            long long cpu = (cpu1.tv_sec - cpu0.tv_sec) * 1000000000LL + cpu1.tv_nsec - cpu0.tv_nsec;
+            fprintf(stderr, "REPLAY_BENCH run=%d blocks=256 keys=20 wall_ns=%lld cpu_ns=%lld notes=%d\n",
+                    run, wall, cpu, db_sapling_note_count_unspent(&db));
+        }
+    }
+    if (projection) wallet_projection_close(projection);
+    app_runtime_set_current(NULL);
+    if (started) db_service_stop(&svc);
+    if (opened) node_db_close(&db);
+    wallet_projection_set_event_log(NULL);
+    if (log) event_log_close(log);
+    wallet_free(f.wallet); free(f.wallet);
+    main_state_free(&f.state);
+    (void)test_rm_rf_recursive(f.dir);
+    return ok;
+}
+
 static bool ndc_replay_restart_checks(struct ndc_replay_fixture *f, struct db_service *svc,
     struct node_db *db, event_log_t *log, const uint8_t *before, size_t bn, int bh)
 {
@@ -4117,6 +4228,7 @@
 static int ndc_check_sapling_replay(void)
 {
     int failures = 0;
+    if (!ndc_bench_range()) return 1;
     struct ndc_replay_fixture f = {0};
     test_make_tmpdir(f.dir, sizeof(f.dir), "node_db_catchup", "replay_range");
     char blocks[320]; snprintf(blocks, sizeof(blocks), "%s/blocks", f.dir);
```

Sparse delta, applied after the dense benchmark diff:

```diff
--- a/tests/harness/src/test_node_db_catchup_service.c
+++ b/tests/harness/src/test_node_db_catchup_service.c
@@ -3132,12 +3132,11 @@
     bool ok = transaction_alloc(tx, 1, 1);
     tx->version = SAPLING_TX_VERSION; tx->overwintered = true;
     tx->version_group_id = SAPLING_VERSION_GROUP_ID;
-    if (height == 1 || height >= 3) {
+    if (height == 1) {
         tx->v_shielded_output = zcl_calloc(2, sizeof(*tx->v_shielded_output), "replay fixture outputs");
         ok = ok && tx->v_shielded_output;
         tx->num_shielded_output = ok ? 2 : 0;
         uint8_t rcm1[32] = {2}, rcm2[32] = {1};
-        if (height >= 3) { rcm1[1] = height; rcm2[1] = height; rcm1[2] = height >> 8; rcm2[2] = height >> 8; }
         if (ok) ok = sapling_compute_cm(d, pk, 9, rcm1, tx->v_shielded_output[0].cm.data) &&
                      ndc_replay_encrypt(f, &tx->v_shielded_output[1], d, pk, rcm2);
         if (ok) {
@@ -4079,14 +4078,14 @@
         ok = ok && clock_gettime(CLOCK_MONOTONIC, &wall1) == 0 &&
              clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu1) == 0 &&
              r.status == SAPLING_REPLAY_COMPLETE && r.last_complete == 256 &&
-             db_sapling_note_count_unspent(&db) == 255 &&
+             db_sapling_note_count_unspent(&db) == 1 &&
              wallet_projection_catch_up(projection) != UINT64_MAX &&
-             wallet_projection_note_count(projection) == 255 &&
-             wallet_projection_total_value_zat(projection) == 2550;
+             wallet_projection_note_count(projection) == 1 &&
+             wallet_projection_total_value_zat(projection) == 10;
         if (ok) {
             long long wall = (wall1.tv_sec - wall0.tv_sec) * 1000000000LL + wall1.tv_nsec - wall0.tv_nsec;
             long long cpu = (cpu1.tv_sec - cpu0.tv_sec) * 1000000000LL + cpu1.tv_nsec - cpu0.tv_nsec;
-            fprintf(stderr, "REPLAY_BENCH run=%d blocks=256 keys=20 wall_ns=%lld cpu_ns=%lld notes=%d\n",
+            fprintf(stderr, "REPLAY_BENCH run=%d blocks=256 outputs=1 keys=20 wall_ns=%lld cpu_ns=%lld notes=%d\n",
                     run, wall, cpu, db_sapling_note_count_unspent(&db));
         }
     }
```

## Strict replay key comparison

A follow-up on 2026-11-07 compared the existing per-block key digest with an
exact comparison of the independently captured public keys. The baseline was
`f8cadbaf062e9456fdb9d68ba0d2360991539e1c`; the candidate patch SHA-256 was
`86dcb20e07f8f99fe01da44552256119b8d48cb7cdcfc4e0aa63a86dc3685ebd`.
The host and compiler were the same as above. A focused catchup test passed;
a deliberate removal of the independent key comparison made the capture-race
fixture fail in both attempts. The full-snapshot check remained enabled.

The separate-process sparse runs used the same serialized input and identity
listed above. Times below are milliseconds, first range followed by retries:

| Order | Mode | Wall | Process CPU |
| --- | --- | --- | --- |
| Baseline first | Hash | 34.50, 24.87, 25.06, 29.65 | 27.93, 26.65, 25.06, 26.59 |
| Baseline first | Compare | 12.49, 12.58, 12.62, 12.02 | 13.02, 13.20, 13.26, 12.65 |
| Candidate first | Compare | 16.48, 17.39, 14.81, 17.22 | 16.34, 18.39, 15.81, 18.11 |
| Candidate first | Hash | 31.65, 17.98, 16.39, 18.81 | 25.26, 18.69, 17.49, 19.89 |

The reversed-order retries overlap. A decrypt-heavy pair also varied materially:
hash first range 1621.58 ms wall / 1599.75 ms CPU, compare first range
1142.55 / 1142.15 ms. This does not establish a causal decrypt-heavy speedup.

To reduce process-order differences, a test-only selector ran both production
range paths in one process. It warmed hash and compare once each, then ran
12 ranges in ABBA order. Every range checked the same endpoint and scan
identity, successful completion, and note/projection count and value. Hash
process CPU times were 26.26, 26.74, 25.36, 20.58, 21.33 and 23.21 ms;
compare times were 22.44, 21.60, 18.63, 17.10, 19.78 and 21.10 ms. Wall
measurements included a 35.63 ms compare outlier and are retained in the raw
log. The registered test passed one of one, with no skips. The synthetic
fixture shows lower CPU in these paired observations; it does not establish a
whole-chain or Android result.

The ABBA log SHA-256 was
`658ce24450fe12651d0286db15fb67de2328105a19a098177029332eb2a772cf`.
Separate sparse logs, in table order, had SHA-256 values
`3ecf0a57e186988331b7c63f8893fe2cf5bcceeab69fb43b7b22cf70006b3c4b`,
`170acb48eb4ea0d66ca9514aff48e6badb0365d05005ba170a1a6b3281527ede`,
`1df390b73ab01d02f562e77991a2842eeabd10c5d8dfd9d96e6f3f3049466a99`, and
`ef9939945e0c4eafba65c6fd2aff164ef7c94d3e427a6f370cdceef69424290d`.
Dense baseline and candidate logs had SHA-256 values
`4ba9b510ce9b96de324d30870a2173bc4cfb76d1867ea61bd800d3a465b78e01` and
`c8a94a20ee7d1f968d4154ad30c57e2b20a16d6c405b0d3a17a292ce94374b24`.
The mutation test log SHA-256 was
`47238e6d0cfafdc4ba5556a0ce8cf934f014d9917fc8dba729ff1d40832e6141`.

For the same-process experiment, apply the candidate patch, then the test-only
diff below, and run `devbuild --wait --project z23 --class normal make -j4
 t-fast-exact ONLY=node_db_catchup_service`. Reverse the test-only diff after
the run; it is not part of the production candidate. Replace each line `␠`
with one ASCII space to reconstruct the exact diff (SHA-256
`ca506a58a3d9e71668213fd5d6cd19fdc818425ff50484055f7168dc68332e7e`).

```diff
--- a/engine/services/src/node_db_catchup_wallet_replay.c
+++ b/engine/services/src/node_db_catchup_wallet_replay.c
@@ -183,10 +183,23 @@
     return true;
 }
␠
+#ifdef ZCL_TESTING
+static bool replay_benchmark_use_hash;
+void node_db_sapling_replay_benchmark_hash(bool enabled)
+{
+    replay_benchmark_use_hash = enabled;
+}
+#endif
+
 static bool replay_keys_current(struct replay_block *job)
 {
     struct sapling_keystore *keys = &job->wallet->sapling_keys;
-    if (job->scan_identity) return replay_keys_match_locked(keys, job->keys);
+#ifdef ZCL_TESTING
+    if (job->scan_identity && !replay_benchmark_use_hash)
+#else
+    if (job->scan_identity)
+#endif
+        return replay_keys_match_locked(keys, job->keys);
     struct replay_keys current = {0};
     return replay_keys_capture_locked(keys, &current) &&
         current.count == job->keys->count &&
--- a/tests/harness/src/test_node_db_catchup_service.c
+++ b/tests/harness/src/test_node_db_catchup_service.c
@@ -22,6 +22,8 @@
 #include "sapling/note_encryption.h"
 #include "sapling/sapling.h"
 #include "support/cleanse.h"
+#include <time.h>
+#include "sha3/sha3.h"
 #ifndef _WIN32
 #include <sys/wait.h>
 #endif
@@ -31,6 +33,7 @@
 void node_db_sapling_replay_test_rollback(struct node_db *db);
 void node_db_sapling_replay_test_after_read(void (*hook)(void *), void *ctx);
 void node_db_sapling_replay_test_after_keys(void (*hook)(void *), void *ctx);
+void node_db_sapling_replay_benchmark_hash(bool enabled);
 void node_db_sapling_replay_test_revalidate_hooks(void (*before)(void *), void (*after)(void *), void *ctx);
 bool boot_test_pending_busy_backoff(int64_t *since, int64_t deadline, int limit_ms);
 void boot_cutover_replay_test_after_current(void (*hook)(void *), void *ctx);
@@ -3084,8 +3087,8 @@
     char dir[256], dbpath[320], logpath[320];
     struct wallet *wallet;
     struct main_state state;
-    struct block_index slots[3];
-    struct uint256 hashes[3], root, note_txid, spend_txid;
+    struct block_index slots[257];
+    struct uint256 hashes[257], root, note_txid, spend_txid;
     int height_offset;
     bool fresh_spend;
     struct incremental_merkle_tree tree;
@@ -4256,6 +4259,117 @@
         ndc_cutover_coordinator(f, svc, db, false);
 }
␠
+static bool ndc_bench_digest_file(const char *dir, uint8_t digest[32])
+{
+    char path[320];
+    int n = snprintf(path, sizeof(path), "%s/blocks/blk00000.dat", dir);
+    if (n < 0 || (size_t)n >= sizeof(path)) return false;
+    FILE *in = fopen(path, "rb");
+    if (!in) return false;
+    struct sha3_256_ctx ctx;
+    sha3_256_init(&ctx);
+    unsigned char buf[4096];
+    size_t count;
+    while ((count = fread(buf, 1, sizeof(buf), in)) != 0) sha3_256_write(&ctx, buf, count);
+    bool ok = !ferror(in);
+    if (fclose(in) != 0) ok = false;
+    if (ok) sha3_256_finalize(&ctx, digest);
+    return ok;
+}
+
+/* Isolated scratch benchmark: real authenticated replay, deterministic input. */
+static bool ndc_bench_range(void)
+{
+    struct ndc_replay_fixture f = {0};
+    test_make_tmpdir(f.dir, sizeof(f.dir), "node_db_catchup", "replay_benchmark");
+    char path[320];
+    snprintf(path, sizeof(path), "%s/blocks", f.dir);
+    bool ok = mkdir(path, 0755) == 0;
+    snprintf(f.dbpath, sizeof(f.dbpath), "%s/node.db", f.dir);
+    snprintf(f.logpath, sizeof(f.logpath), "%s/events.log", f.dir);
+    f.wallet = zcl_calloc(1, sizeof(*f.wallet), "replay benchmark wallet");
+    if (!f.wallet) return false;
+    wallet_init(f.wallet);
+    ok = ok && wallet_readiness_initialize(f.wallet, WALLET_READINESS_PENDING, true, 1);
+    main_state_init(&f.state);
+    sapling_tree_init(&f.tree);
+    uint8_t seed[32] = {1}, d[11], pk[32];
+    ok = ok && sapling_keystore_set_seed(&f.wallet->sapling_keys, seed) &&
+        sapling_keystore_new_address(&f.wallet->sapling_keys, d, pk);
+    for (int h = 1; ok && h <= 256; ++h)
+        ok = ndc_replay_write_fixture_block(&f, h, d, pk);
+    struct sapling_keystore *ks = &f.wallet->sapling_keys;
+    struct sapling_key_entry original = ks->keys[0];
+    for (size_t i = 0; i < 19; ++i) {
+        ks->keys[i] = original;
+        memset(ks->keys[i].ivk, 0, sizeof(ks->keys[i].ivk));
+        ks->keys[i].ivk[0] = (uint8_t)(i + 2);
+        if (!memcmp(ks->keys[i].ivk, original.ivk, 32)) ks->keys[i].ivk[1] = 1;
+    }
+    ks->keys[19] = original;
+    ks->num_keys = 20;
+    event_log_t *log = ok ? event_log_open(f.logpath) : NULL;
+    wallet_projection_set_event_log(log);
+    struct node_db db = {0};
+    bool opened = log && node_db_open(&db, f.dbpath);
+    struct db_service svc;
+    db_service_init(&svc);
+    bool started = opened && db_service_attach(&svc, &db) && db_service_start_test_worker(&svc);
+    struct app_runtime_context runtime = {.db_service = &svc};
+    app_runtime_set_current(&runtime);
+    uint8_t identity[32];
+    ok = started && wallet_scan_identity(f.wallet, identity);
+    snprintf(path, sizeof(path), "%s/projection.db", f.dir);
+    wallet_projection_t *projection = ok ? wallet_projection_open(path, log) : NULL;
+    ok = ok && projection;
+    uint8_t file_digest[32];
+    ok = ok && ndc_bench_digest_file(f.dir, file_digest);
+    if (ok) {
+        fprintf(stderr, "REPLAY_BENCH scan_identity=");
+        for (size_t i = 0; i < 32; ++i) fprintf(stderr, "%02x", identity[i]);
+        fprintf(stderr, " archive_sha3=");
+        for (size_t i = 0; i < 32; ++i) fprintf(stderr, "%02x", file_digest[i]);
+        fprintf(stderr, "\n");
+    }
+    fprintf(stderr, "REPLAY_BENCH endpoint=");
+    for (size_t i = 0; i < 32; ++i) fprintf(stderr, "%02x", f.hashes[256].data[i]);
+    fprintf(stderr, "\n");
+    for (int run = -2; ok && run < 12; ++run) {
+        bool hash = run < 0 ? run == -2 : run % 4 == 0 || run % 4 == 3;
+        node_db_sapling_replay_benchmark_hash(hash);
+        struct timespec wall0, wall1, cpu0, cpu1;
+        ok = clock_gettime(CLOCK_MONOTONIC, &wall0) == 0 &&
+             clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu0) == 0;
+        struct sapling_replay_result r = node_db_catchup_sapling_replay_at_reference(
+            &svc, &db, &f.state, f.wallet, f.dir, 1, 256, 256, f.hashes[256].data,
+            SAPLING_REPLAY_DISCOVER, f.hashes[256].data, identity, NULL);
+        ok = ok && clock_gettime(CLOCK_MONOTONIC, &wall1) == 0 &&
+             clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu1) == 0 &&
+             r.status == SAPLING_REPLAY_COMPLETE && r.last_complete == 256 &&
+             db_sapling_note_count_unspent(&db) == 1 &&
+             wallet_projection_catch_up(projection) != UINT64_MAX &&
+             wallet_projection_note_count(projection) == 1 &&
+             wallet_projection_total_value_zat(projection) == 10;
+        if (ok) {
+            long long wall = (wall1.tv_sec - wall0.tv_sec) * 1000000000LL + wall1.tv_nsec - wall0.tv_nsec;
+            long long cpu = (cpu1.tv_sec - cpu0.tv_sec) * 1000000000LL + cpu1.tv_nsec - cpu0.tv_nsec;
+            fprintf(stderr, "REPLAY_BENCH run=%d mode=%s blocks=256 outputs=1 keys=20 wall_ns=%lld cpu_ns=%lld notes=%d\n",
+                    run, hash ? "hash" : "compare", wall, cpu, db_sapling_note_count_unspent(&db));
+        }
+    }
+    node_db_sapling_replay_benchmark_hash(false);
+    if (projection) wallet_projection_close(projection);
+    app_runtime_set_current(NULL);
+    if (started) db_service_stop(&svc);
+    if (opened) node_db_close(&db);
+    wallet_projection_set_event_log(NULL);
+    if (log) event_log_close(log);
+    wallet_free(f.wallet); free(f.wallet);
+    main_state_free(&f.state);
+    (void)test_rm_rf_recursive(f.dir);
+    return ok;
+}
+
 static bool ndc_replay_restart_checks(struct ndc_replay_fixture *f, struct db_service *svc,
     struct node_db *db, event_log_t *log, const uint8_t *before, size_t bn, int bh)
 {
@@ -4382,6 +4496,7 @@
 static int ndc_check_sapling_replay(void)
 {
     int failures = 0;
+    if (!ndc_bench_range()) return 1;
     struct ndc_replay_fixture f = {0};
     test_make_tmpdir(f.dir, sizeof(f.dir), "node_db_catchup", "replay_range");
     char blocks[320]; snprintf(blocks, sizeof(blocks), "%s/blocks", f.dir);
```
