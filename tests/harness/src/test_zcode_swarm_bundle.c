/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * zcode_swarm scenario checks for `fleet bundle offer` / `fleet bundle
 * fetch` (tools/command/native_fleet_bundle.c): a bounded file (a git
 * bundle) moves from one node to another as an ordinary unsigned content.v2
 * package over the UNCHANGED swarm wire — two real engines, two real stores,
 * no network, no Tor. Covers byte-identical round trips at 1 B, 1 MiB + 1 B
 * (two chunks) and 5 MiB; the sha256 mismatch that writes nothing; the
 * over-cap, existing-out and IP-literal-peer refusals; and that the blob
 * surface and its 8 KiB cap are unchanged. */

#include "test/test_core.h"

#include "base/hex.h"
#include "command/native_command.h"
#include "command/native_fleet_bundle.h"
#include "json/json.h"
#include "vcs/blob_store.h"
#include "vcs/bundle_carry.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test/test_zcode_swarm_priv.h"

#define BUNDLE_SEEDER_HANDLE 7u  /* the seeder's handle for the leecher */
#define BUNDLE_LEECH_HANDLE 9u   /* the leecher's handle for the seeder */
#define BUNDLE_ROUNDS 96
#define BUNDLE_ONION \
    "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"

struct bundle_pair {
    struct sw_node seed;
    struct sw_node leech;
};

static void bundle_fill(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)((i * 131u + 7u) ^ (i >> 8) ^ (i >> 17));
}

static bool bundle_write_file(const char *path, const uint8_t *buf,
                              size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fwrite(buf, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

static bool bundle_pair_open(struct bundle_pair *p, const char *tag)
{
    char a[32], b[32];
    (void)snprintf(a, sizeof(a), "%sseed", tag);
    (void)snprintf(b, sizeof(b), "%sleech", tag);
    memset(p, 0, sizeof(*p));
    if (!sw_node_open(&p->seed, a, sw_score_contributor) ||
        !sw_node_open(&p->leech, b, sw_score_contributor))
        return false;
    uint8_t key_seed[33], key_leech[33];
    sw_key(81, key_leech);
    sw_key(82, key_seed);
    return vcs_swarm_engine_peer_add(p->seed.engine, BUNDLE_SEEDER_HANDLE,
                                     key_leech) &&
           vcs_swarm_engine_peer_add(p->leech.engine, BUNDLE_LEECH_HANDLE,
                                     key_seed);
}

static void bundle_pair_close(struct bundle_pair *p)
{
    sw_node_close(&p->seed);
    sw_node_close(&p->leech);
    test_rm_rf_recursive(p->seed.datadir);
    test_rm_rf_recursive(p->leech.datadir);
}

/* Deliver every queued frame from `from` for `to` and feed any DATA reply
 * back. */
static void bundle_deliver(struct sw_node *from, uint64_t from_handle_for_to,
                           struct sw_node *to, uint64_t to_handle_for_from,
                           uint64_t now)
{
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t frame_len = 0;
    uint64_t target = 0;
    while (vcs_swarm_engine_next_outbound(from->engine, from_handle_for_to,
                                          &target, frame, &frame_len)) {
        struct vcs_swarm_frame_result served = vcs_swarm_engine_handle_frame(
            to->engine, to_handle_for_from, frame, frame_len, SW_DAY, now);
        if (served.reply && served.reply_len > 0) {
            struct vcs_swarm_frame_result got = vcs_swarm_engine_handle_frame(
                from->engine, from_handle_for_to, served.reply,
                served.reply_len, SW_DAY, now);
            free(got.reply);
        }
        free(served.reply);
    }
}

static void bundle_make_path(char *out, size_t cap, const struct sw_node *n,
                             const char *leaf)
{
    (void)snprintf(out, cap, "%s/%s", n->datadir, leaf);
}

/* Offer `len` pattern bytes from the seeder and drain its ANNOUNCE. */
static bool bundle_offer(struct bundle_pair *p, size_t len,
                         struct zcl_fleet_bundle_outcome *o, uint8_t **orig)
{
    *orig = malloc(len);
    if (!*orig)
        return false;
    bundle_fill(*orig, len);
    char path[1200];
    bundle_make_path(path, sizeof(path), &p->seed, "offered.bundle");
    if (!bundle_write_file(path, *orig, len))
        return false;
    if (zcl_fleet_bundle_offer(p->seed.store, p->seed.engine, path, o) !=
        ZCL_FLEET_BUNDLE_DONE)
        return false;
    bundle_deliver(&p->seed, BUNDLE_SEEDER_HANDLE, &p->leech,
                   BUNDLE_LEECH_HANDLE, 1);
    return true;
}

/* Drive the leecher's fetch step against the seeder until it ends. */
static enum zcl_fleet_bundle_status bundle_fetch_loop(
    struct bundle_pair *p, struct zcl_fleet_bundle_fetch_args *a,
    struct zcl_fleet_bundle_outcome *o)
{
    enum zcl_fleet_bundle_status st = ZCL_FLEET_BUNDLE_PENDING;
    for (int round = 0; round < BUNDLE_ROUNDS; round++) {
        a->day = SW_DAY;
        a->now = (uint64_t)(round + 2);
        st = zcl_fleet_bundle_fetch_step(p->leech.store, p->leech.engine, a,
                                         o);
        if (st != ZCL_FLEET_BUNDLE_PENDING)
            return st;
        vcs_swarm_engine_tick(p->leech.engine, SW_DAY, a->now);
        bundle_deliver(&p->leech, BUNDLE_LEECH_HANDLE, &p->seed,
                       BUNDLE_SEEDER_HANDLE, a->now);
    }
    return st;
}

static bool bundle_file_equals(const char *path, const uint8_t *want,
                               size_t len, bool *mode_0600)
{
    struct stat st;
    if (stat(path, &st) != 0 || (size_t)st.st_size != len)
        return false;
    *mode_0600 = (st.st_mode & 0777) == 0600;
    uint8_t *got = malloc(len);
    FILE *f = got ? fopen(path, "rb") : NULL;
    bool same = f && fread(got, 1, len, f) == len &&
                memcmp(got, want, len) == 0;
    if (f)
        fclose(f);
    free(got);
    return same;
}

static void bundle_args(struct zcl_fleet_bundle_fetch_args *a,
                        const struct zcl_fleet_bundle_outcome *offered,
                        const char *out_path)
{
    memset(a, 0, sizeof(*a));
    memcpy(a->root, offered->root, 32);
    memcpy(a->sha256, offered->sha256, 32);
    a->size = offered->size;
    a->out_path = out_path;
}

/* One round trip of `len` bytes; also pins the public shape to BUNDLE. */
static int bundle_case_roundtrip(const char *name, const char *tag,
                                 size_t len)
{
    int failures = 0;
    struct bundle_pair p;
    struct zcl_fleet_bundle_outcome offered, got;
    uint8_t *orig = NULL;
    char label[96], out_path[1200];
    if (!bundle_pair_open(&p, tag) || !bundle_offer(&p, len, &offered, &orig)) {
        printf("  zcode_swarm: bundle %s fixture... FAIL\n", name);
        free(orig);
        bundle_pair_close(&p);
        return 1;
    }
    struct vcs_package_public_verdict verdict;
    (void)snprintf(label, sizeof(label), "bundle %s: seeder serves it as shape bundle", name);
    SW_CHECK(label, vcs_package_public_shape_classify(
                        p.seed.store, offered.root, &verdict) ==
                        VCS_PACKAGE_PUBLIC_BUNDLE);
    struct zcl_fleet_bundle_fetch_args a;
    bundle_make_path(out_path, sizeof(out_path), &p.leech, "received.bundle");
    bundle_args(&a, &offered, out_path);
    enum zcl_fleet_bundle_status st = bundle_fetch_loop(&p, &a, &got);
    bool mode_ok = false;
    (void)snprintf(label, sizeof(label), "bundle %s: fetch completes", name);
    SW_CHECK(label, st == ZCL_FLEET_BUNDLE_DONE);
    (void)snprintf(label, sizeof(label), "bundle %s: out is byte-identical", name);
    SW_CHECK(label, st == ZCL_FLEET_BUNDLE_DONE &&
                        bundle_file_equals(out_path, orig, len, &mode_ok) &&
                        got.size == len &&
                        memcmp(got.sha256, offered.sha256, 32) == 0);
    (void)snprintf(label, sizeof(label), "bundle %s: out is mode 0600", name);
    SW_CHECK(label, mode_ok);
    free(orig);
    bundle_pair_close(&p);
    return failures;
}

/* sha256 / size / shape / existing-out refusals against a complete store. */
static int bundle_case_refusals(void)
{
    int failures = 0;
    struct bundle_pair p;
    struct zcl_fleet_bundle_outcome offered, o;
    uint8_t *orig = NULL;
    if (!bundle_pair_open(&p, "brf") ||
        !bundle_offer(&p, 3000, &offered, &orig)) {
        printf("  zcode_swarm: bundle refusal fixture... FAIL\n");
        free(orig);
        bundle_pair_close(&p);
        return 1;
    }
    char out_path[1200];
    struct zcl_fleet_bundle_fetch_args a;
    bundle_make_path(out_path, sizeof(out_path), &p.leech, "never.bundle");

    bundle_args(&a, &offered, out_path);
    a.sha256[0] ^= 0x01;
    SW_CHECK("bundle: a sha256 mismatch is refused",
             bundle_fetch_loop(&p, &a, &o) == ZCL_FLEET_BUNDLE_REFUSED &&
             strcmp(o.code, "SHA256_MISMATCH") == 0);
    SW_CHECK("bundle: a sha256 mismatch writes nothing",
             access(out_path, F_OK) != 0);

    bundle_args(&a, &offered, out_path);
    a.size = offered.size + 1u;
    SW_CHECK("bundle: a wrong size is refused",
             zcl_fleet_bundle_fetch_step(p.seed.store, p.seed.engine, &a,
                                         &o) == ZCL_FLEET_BUNDLE_REFUSED &&
             strcmp(o.code, "SIZE_MISMATCH") == 0 &&
             access(out_path, F_OK) != 0);

    bundle_args(&a, &offered, out_path);
    a.size = 0;
    SW_CHECK("bundle: size 0 is refused",
             zcl_fleet_bundle_fetch_step(p.seed.store, p.seed.engine, &a,
                                         &o) == ZCL_FLEET_BUNDLE_REFUSED &&
             strcmp(o.code, "BAD_SIZE") == 0);
    a.size = (uint64_t)VCS_BUNDLE_MAX_BYTES + 1u;
    SW_CHECK("bundle: a size over 5 MiB is refused",
             zcl_fleet_bundle_fetch_step(p.seed.store, p.seed.engine, &a,
                                         &o) == ZCL_FLEET_BUNDLE_REFUSED &&
             strcmp(o.code, "BAD_SIZE") == 0);

    bundle_args(&a, &offered, out_path);
    char existing[1200];
    bundle_make_path(existing, sizeof(existing), &p.seed, "offered.bundle");
    a.out_path = existing;
    SW_CHECK("bundle: an existing out is refused and left alone",
             zcl_fleet_bundle_fetch_step(p.seed.store, p.seed.engine, &a,
                                         &o) == ZCL_FLEET_BUNDLE_REFUSED &&
             strcmp(o.code, "OUT_EXISTS") == 0);
    {
        bool unused = false;
        SW_CHECK("bundle: the existing out kept its bytes",
                 bundle_file_equals(existing, orig, 3000, &unused));
    }
    free(orig);
    bundle_pair_close(&p);
    return failures;
}

/* A blob root is not a bundle: the fetch refuses it by shape. */
static int bundle_case_blob_is_not_bundle(void)
{
    int failures = 0;
    struct bundle_pair p;
    memset(&p, 0, sizeof(p));
    if (!bundle_pair_open(&p, "bbl")) {
        printf("  zcode_swarm: bundle blob fixture... FAIL\n");
        bundle_pair_close(&p);
        return 1;
    }
    uint8_t blob[300], root[32];
    memset(blob, 0x5a, sizeof(blob));
    SW_CHECK("blob: put still works",
             vcs_blob_put_to(p.seed.store, blob, sizeof(blob), root) ==
                 VCS_BLOB_OK);
    struct zcl_fleet_bundle_fetch_args a;
    memset(&a, 0, sizeof(a));
    memcpy(a.root, root, 32);
    a.size = sizeof(blob);
    char out_path[1200];
    bundle_make_path(out_path, sizeof(out_path), &p.seed, "blobout");
    a.out_path = out_path;
    struct zcl_fleet_bundle_outcome o;
    SW_CHECK("bundle: a blob root is refused as not a bundle",
             zcl_fleet_bundle_fetch_step(p.seed.store, p.seed.engine, &a,
                                         &o) == ZCL_FLEET_BUNDLE_REFUSED &&
             strcmp(o.code, "NOT_A_BUNDLE") == 0 &&
             access(out_path, F_OK) != 0);
    bundle_pair_close(&p);
    return failures;
}

/* The blob surface and its 8192 cap are untouched. */
static int bundle_case_blob_cap_unchanged(void)
{
    int failures = 0;
    uint8_t big[VCS_BLOB_MAX_BYTES + 1u], root[32];
    memset(big, 0x33, sizeof(big));
    SW_CHECK("blob: the cap constant is still 8192",
             VCS_BLOB_MAX_BYTES == 8192u);
    SW_CHECK("blob: 8192 bytes still fit",
             vcs_blob_root_of(big, VCS_BLOB_MAX_BYTES, root) ==
                 VCS_BLOB_OK);
    SW_CHECK("blob: 8193 bytes are still refused",
             vcs_blob_root_of(big, sizeof(big), root) ==
                 VCS_BLOB_ERR_TOO_LARGE);
    return failures;
}

/* Offer refuses a missing file, an empty one and one over the cap. */
static int bundle_case_offer_refusals(void)
{
    int failures = 0;
    struct bundle_pair p;
    if (!bundle_pair_open(&p, "bof")) {
        printf("  zcode_swarm: bundle offer fixture... FAIL\n");
        bundle_pair_close(&p);
        return 1;
    }
    char path[1200];
    struct zcl_fleet_bundle_outcome o;
    bundle_make_path(path, sizeof(path), &p.seed, "absent.bundle");
    SW_CHECK("bundle: offering a missing file is refused",
             zcl_fleet_bundle_offer(p.seed.store, p.seed.engine, path, &o) ==
                 ZCL_FLEET_BUNDLE_REFUSED &&
             strcmp(o.code, "FILE_UNREADABLE") == 0);
    uint8_t *big = malloc((size_t)VCS_BUNDLE_MAX_BYTES + 1u);
    if (!big) {
        bundle_pair_close(&p);
        return failures + 1;
    }
    bundle_fill(big, (size_t)VCS_BUNDLE_MAX_BYTES + 1u);
    bundle_make_path(path, sizeof(path), &p.seed, "big.bundle");
    SW_CHECK("bundle: a file of 5 MiB + 1 B is written",
             bundle_write_file(path, big, (size_t)VCS_BUNDLE_MAX_BYTES + 1u));
    free(big);
    SW_CHECK("bundle: offering a file over 5 MiB is refused",
             zcl_fleet_bundle_offer(p.seed.store, p.seed.engine, path, &o) ==
                 ZCL_FLEET_BUNDLE_REFUSED &&
             strcmp(o.code, "FILE_TOO_LARGE") == 0);
    bundle_make_path(path, sizeof(path), &p.seed, "empty.bundle");
    SW_CHECK("bundle: an empty file is written", bundle_write_file(path, (const uint8_t *)"", 0));
    SW_CHECK("bundle: offering an empty file is refused",
             zcl_fleet_bundle_offer(p.seed.store, p.seed.engine, path, &o) ==
                 ZCL_FLEET_BUNDLE_REFUSED &&
             strcmp(o.code, "FILE_EMPTY") == 0);
    SW_CHECK("bundle: a relative file path is refused",
             zcl_fleet_bundle_offer(p.seed.store, p.seed.engine, "rel.bundle",
                                    &o) == ZCL_FLEET_BUNDLE_REFUSED);
    bundle_pair_close(&p);
    return failures;
}

/* The fetch handler validates before it contacts anything: an IP-literal
 * peer, a clearnet peer and a bad root are refused by name. */
static bool bundle_handler_refuses(const char *peer, const char *root_hex,
                                   const char *want_code)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    json_push_kv_str(&input, "root", root_hex);
    json_push_kv_str(&input, "sha256", root_hex);
    json_push_kv_int(&input, "size", 10);
    json_push_kv_str(&input, "out", "/nonexistent-zbundle-dir/never.bundle");
    if (peer)
        json_push_kv_str(&input, "peer", peer);
    struct zcl_command_request request = { .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.fleet_bundle_fetch.v1");
    zcl_native_handle_fleet_bundle_fetch(&request, &reply);
    bool ok = reply.status != ZCL_COMMAND_STATUS_PASSED &&
              strcmp(reply.error.code, want_code) == 0;
    zcl_command_reply_free(&reply);
    json_free(&input);
    return ok;
}

static int bundle_case_peer_rules(void)
{
    int failures = 0;
    const char *good_root =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    SW_CHECK("bundle: a v3 onion name is an accepted peer",
             zcl_fleet_bundle_peer_is_onion(BUNDLE_ONION) &&
             !zcl_fleet_bundle_peer_is_onion("127.0.0.1") &&
             !zcl_fleet_bundle_peer_is_onion("10.0.0.5:8033") &&
             !zcl_fleet_bundle_peer_is_onion("[::1]:8033") &&
             !zcl_fleet_bundle_peer_is_onion("example.com") &&
             !zcl_fleet_bundle_peer_is_onion("short.onion"));
    SW_CHECK("bundle: an IP-literal peer is refused by the handler",
             bundle_handler_refuses("203.0.113.9:8033", good_root,
                                    "BAD_PEER"));
    SW_CHECK("bundle: a clearnet host peer is refused by the handler",
             bundle_handler_refuses("example.com", good_root, "BAD_PEER"));
    SW_CHECK("bundle: a bad root is refused by the handler",
             bundle_handler_refuses(NULL, "zz", "BAD_ROOT"));
    return failures;
}

int t_swarm_bundle_transfer(void)
{
    int failures = 0;
    failures += bundle_case_roundtrip("1 B", "b1", 1u);
    failures += bundle_case_roundtrip("1 MiB + 1 B", "b2",
                                      (size_t)VCS_PACKAGE_CHUNK_BYTES + 1u);
    failures += bundle_case_roundtrip("5 MiB", "b5",
                                      (size_t)VCS_BUNDLE_MAX_BYTES);
    failures += bundle_case_refusals();
    failures += bundle_case_blob_is_not_bundle();
    failures += bundle_case_blob_cap_unchanged();
    failures += bundle_case_offer_refusals();
    failures += bundle_case_peer_rules();
    return failures;
}
