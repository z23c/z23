/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves unsigned copied-image CAS identities require independent
 * current policy, exact bounded bytes and opaque evidence; no guest executes. */
#include "test/test_core.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/sha256.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "services/guest_image_admission.h"
#include "vcs/vcs_object.h"

static const char public_digest[] =
    "2445a0ca747bb28eac52c8c2bb861ee9be06f3c7353587d88e3c3fcbb832b2f4";
static const char public_v2_digest[] =
    "21a6934e16305c09a8a8ab4c0237fc50959bf2315ef0239954c84bc7c91da437";
static const char public_v5_digest[] =
    "f4cad5bba8ad562996b5bd781b3debb2286a910f5aae70014927c6aea1980d4d";
static const char public_v6_digest[] =
    "db2440c0ce534decbac8aac94fade789c8978e5d145f1795fa216603a7404af5";
static const char public_v7_digest[] =
    "ac1dd2f5260aa64d2ba9cf30c13927709ff7f427709571dd65521051cf44b57c";
struct gia_test_policy {
    uint8_t root[32], digest[32];
    unsigned calls, refuse_at;
    bool enabled;
};
static bool gia_test_grant(void *ctx, const uint8_t root[32],
                           const struct vcs_guest_image_observation *o)
{
    struct gia_test_policy *p = ctx;
    ++p->calls;
    return p->enabled && (!p->refuse_at || p->calls < p->refuse_at) &&
           memcmp(root, p->root, 32) == 0 &&
           (!o || memcmp(o->image_sha256, p->digest, 32) == 0);
}
static bool gia_test_load(const char *path, uint64_t maximum, uint8_t **out, size_t *bytes)
{
    *out = NULL; *bytes = 0;
    struct platform_positioned_file f;
    platform_positioned_file_init(&f);
    struct platform_positioned_file_snapshot before, after;
    if (!platform_positioned_file_open(&f, path)) return false;
    bool ok = platform_positioned_file_snapshot(&f, &before) &&
              before.size > 0 && before.size <= maximum &&
              before.size <= SIZE_MAX;
    uint8_t *data = ok ? zcl_malloc((size_t)before.size, "public-guest-test-image") : NULL;
    ok = ok && data != NULL;
    if (ok) {
        ok = platform_positioned_file_read(&f, data, (size_t)before.size, 0) ==
             (int64_t)before.size &&
             platform_positioned_file_snapshot(&f, &after) &&
             platform_positioned_file_snapshot_equal(&before, &after);
    }
    platform_positioned_file_close(&f);
    if (!ok) { free(data); return false; }
    *out = data; *bytes = (size_t)before.size;
    return true;
}
static void gia_test_sha(const uint8_t *image, size_t bytes, uint8_t digest[32])
{
    struct sha256_ctx h;
    sha256_init(&h); sha256_write(&h, image, bytes); sha256_finalize(&h, digest);
}
static int gia_codec_controls(void)
{
    int failures = 0;
    struct vcs_guest_image_observation o = {0}, parsed;
    memset(o.image.root, 1, 32); memset(o.image_sha256, 2, 32);
    o.image.bytes = 128;
    for (size_t i = 0; i < 3; ++i) {
        memset(o.evidence[i].root, (int)i + 3, 32); o.evidence[i].bytes = 7;
    }
    uint8_t wire[VCS_GUEST_IMAGE_WIRE_BYTES], changed[VCS_GUEST_IMAGE_WIRE_BYTES];
    TEST("copied observation exact codec and checked caller caps") {
        ASSERT(vcs_guest_image_observation_encode(&o, wire));
        ASSERT(vcs_guest_image_observation_decode(wire, sizeof(wire), &parsed));
        ASSERT(parsed.image.bytes == 128 && parsed.evidence[2].bytes == 7);
        ASSERT(memcmp(parsed.image.root, o.image.root, 32) == 0);
        ASSERT(vcs_guest_image_observation_budget(&parsed, 128, 357));
        ASSERT(!vcs_guest_image_observation_budget(&parsed, 127, 357));
        ASSERT(!vcs_guest_image_observation_budget(&parsed, 128, 356));
        ASSERT(!vcs_guest_image_observation_decode(wire, sizeof(wire) - 1, &parsed));
        for (size_t i = 0; i < 16; ++i) {
            memcpy(changed, wire, sizeof(wire)); changed[i] ^= 0x40;
            ASSERT(!vcs_guest_image_observation_decode(changed, sizeof(changed), &parsed));
        }
        o.image.bytes = UINT64_MAX;
        ASSERT(!vcs_guest_image_observation_encode(&o, changed));
        o.image.bytes = 128; o.evidence[0].bytes = UINT64_MAX;
        ASSERT(!vcs_guest_image_observation_budget(&o, UINT64_MAX, UINT64_MAX));
        PASS();
    }
_test_next:
    return failures;
}
static bool gia_test_stage(const char *repo, const uint8_t *image, size_t bytes,
                            struct vcs_guest_image_observation *o, uint8_t root[32])
{
    memset(o, 0, sizeof(*o));
    if (!vcs_object_store_init(repo)) return false;
    o->image.bytes = bytes;
    gia_test_sha(image, bytes, o->image_sha256);
    if (!vcs_object_put(repo, image, bytes, VCS_TAG_BLOB, o->image.root)) return false;
    static const char *const opaque[3] = {
        "PUBLIC test provenance; semantics unverified",
        "PUBLIC test license inventory; not legal acceptance",
        "PUBLIC test source inventory; not reproduction"
    };
    for (size_t i = 0; i < 3; ++i) {
        o->evidence[i].bytes = strlen(opaque[i]);
        if (!vcs_object_put(repo, (const uint8_t *)opaque[i], strlen(opaque[i]),
                            VCS_TAG_BLOB, o->evidence[i].root)) return false;
    }
    uint8_t wire[VCS_GUEST_IMAGE_WIRE_BYTES];
    return vcs_guest_image_observation_encode(o, wire) &&
           vcs_object_put(repo, wire, sizeof(wire), VCS_TAG_BLOB, root);
}
static int gia_adapter_controls(const char *repo,
    const struct vcs_guest_image_observation *o, struct gia_test_policy *policy)
{
    int failures = 0;
    uint64_t budget = VCS_GUEST_IMAGE_WIRE_BYTES + o->image.bytes;
    for (size_t i = 0; i < 3; ++i) budget += o->evidence[i].bytes;
    struct guest_image_admission *h = NULL;
    const uint8_t *copy = NULL; size_t bytes = 0;
    TEST("actual PUBLIC2445 copy requires current independent grant, no execution") {
        ASSERT(guest_image_admission_open(repo, policy->root, o->image.bytes,
                                         budget, gia_test_grant, policy, &h).ok);
        ASSERT(h != NULL);
        ASSERT(guest_image_admission_bytes(h, &copy, &bytes).ok);
        ASSERT(bytes == o->image.bytes);
        uint8_t digest[32]; gia_test_sha(copy, bytes, digest);
        ASSERT(memcmp(digest, policy->digest, 32) == 0);
        policy->enabled = false;
        ASSERT(!guest_image_admission_bytes(h, &copy, &bytes).ok);
        ASSERT(copy == NULL && bytes == 0);
        guest_image_admission_close(&h); guest_image_admission_close(&h);
        ASSERT(h == NULL);
        ASSERT(!guest_image_admission_open(repo, policy->root, o->image.bytes,
                                          budget, gia_test_grant, policy, &h).ok);
        policy->enabled = true;
        ASSERT(!guest_image_admission_open(repo, policy->root, o->image.bytes,
                                          budget, NULL, policy, &h).ok);
        ASSERT(!guest_image_admission_open(repo, policy->root, o->image.bytes - 1,
                                          budget, gia_test_grant, policy, &h).ok);
        ASSERT(!guest_image_admission_open(repo, policy->root, o->image.bytes,
                                          budget - 1, gia_test_grant, policy, &h).ok);
        policy->calls = 0; policy->refuse_at = 3;
        ASSERT(!guest_image_admission_open(repo, policy->root, o->image.bytes,
                                          budget, gia_test_grant, policy, &h).ok);
        ASSERT(h == NULL && policy->calls == 3);
        policy->refuse_at = 0;
        uint8_t wrong[32]; memcpy(wrong, policy->root, 32); wrong[0] ^= 1;
        ASSERT(!guest_image_admission_open(repo, wrong, o->image.bytes,
                                          budget, gia_test_grant, policy, &h).ok);
        PASS();
    }
_test_next:
    guest_image_admission_close(&h);
    return failures;
}
int test_guest_image_admission(void);
static int gia_corrupt_controls(const char *repo,
    const struct vcs_guest_image_observation *original, struct gia_test_policy *policy,
    uint8_t *image, size_t image_bytes)
{
    int failures = 0;
    uint8_t original_root[32]; memcpy(original_root, policy->root, 32);
    struct vcs_guest_image_observation changed = *original;
    uint64_t budget = VCS_GUEST_IMAGE_WIRE_BYTES + original->image.bytes;
    for (size_t i = 0; i < 3; ++i) budget += original->evidence[i].bytes;
    uint8_t wire[VCS_GUEST_IMAGE_WIRE_BYTES];
    struct guest_image_admission *h = NULL;
    TEST("CAS missing evidence and copied digest are independently refused") {
        changed.image_sha256[0] ^= 1;
        ASSERT(vcs_guest_image_observation_encode(&changed, wire));
        ASSERT(vcs_object_put(repo, wire, sizeof(wire), VCS_TAG_BLOB, policy->root));
        /* Owner rejects another image even though its unsigned root is valid. */
        ASSERT(!guest_image_admission_open(repo, policy->root, original->image.bytes,
                                          budget, gia_test_grant, policy, &h).ok);
        changed = *original;
        image[0] ^= 1;
        bool stored = vcs_object_put(repo, image, image_bytes, VCS_TAG_BLOB, changed.image.root);
        image[0] ^= 1;
        ASSERT(stored);
        ASSERT(vcs_guest_image_observation_encode(&changed, wire));
        ASSERT(vcs_object_put(repo, wire, sizeof(wire), VCS_TAG_BLOB, policy->root));
        ASSERT(!guest_image_admission_open(repo, policy->root, original->image.bytes,
                                          budget, gia_test_grant, policy, &h).ok);
        changed = *original;
        memset(changed.evidence[0].root, 0x5a, 32);
        ASSERT(vcs_guest_image_observation_encode(&changed, wire));
        ASSERT(vcs_object_put(repo, wire, sizeof(wire), VCS_TAG_BLOB, policy->root));
        ASSERT(!guest_image_admission_open(repo, policy->root, original->image.bytes,
                                          budget, gia_test_grant, policy, &h).ok);
        changed = *original; changed.image.bytes -= 1;
        ASSERT(vcs_guest_image_observation_encode(&changed, wire));
        ASSERT(vcs_object_put(repo, wire, sizeof(wire), VCS_TAG_BLOB, policy->root));
        ASSERT(!guest_image_admission_open(repo, policy->root, original->image.bytes,
                                          budget, gia_test_grant, policy, &h).ok);
        changed = *original;
        ASSERT(vcs_guest_image_observation_encode(&changed, wire));
        wire[8] = 2;
        ASSERT(vcs_object_put(repo, wire, sizeof(wire), VCS_TAG_BLOB, policy->root));
        ASSERT(!guest_image_admission_open(repo, policy->root, original->image.bytes,
                                          budget, gia_test_grant, policy, &h).ok);
        ASSERT(h == NULL);
        changed = *original;
        ASSERT(vcs_guest_image_observation_encode(&changed, wire));
        memset(policy->root, 0x6b, 32);
        ASSERT(vcs_object_put_addressed(repo, policy->root, wire, sizeof(wire)));
        ASSERT(!guest_image_admission_open(repo, policy->root, original->image.bytes,
                                          budget, gia_test_grant, policy, &h).ok);
        ASSERT(h == NULL);
        PASS();
    }
_test_next:
    memcpy(policy->root, original_root, 32);
    guest_image_admission_close(&h);
    return failures;
}
/* Optional retained PUBLIC capture uses original opaque inputs, not markers.
 * Inputs are prepared beside the new CAS root; no legal/source completeness
 * or immutable namespace claim follows from their observed bytes. */
static bool gia_capture_input(const char *inputs, const char *name,
                              const char *hash, size_t expected,
                              uint8_t **data, size_t *size)
{
    char path[900]; uint8_t actual[32], wanted[32];
    int len = snprintf(path, sizeof(path), "%s/%s", inputs, name);
    bool ok = len >= 0 && (size_t)len < sizeof(path) &&
              gia_test_load(path, VCS_GUEST_EVIDENCE_MAX_BYTES, data, size);
    if (ok) {
        gia_test_sha(*data, *size, actual);
        ok = *size == expected && zcl_hex_decode(hash, wanted, 32) &&
             memcmp(actual, wanted, 32) == 0;
    }
    return ok;
}
static void gia_capture_paired_provenance(unsigned image_kind, size_t index,
    const char **hash, size_t *size)
{
    if (index != 0) return;
    if (image_kind == 5) {
        *hash = "9c1da25b08e7d5dcacad8853b2afcb81d166bfe27c1b45a37ca7a5d6df338c41";
        *size = 4091;
    } else if (image_kind == 6) {
        *hash = "a03def688bec20ffffe36f3235e47fdbe51dce364061632eaee37e65dd5ae2b7";
        *size = 4056;
    }
}
static void gia_capture_combined_metadata(unsigned image_kind, size_t index,
    const char **hash, size_t *size)
{
    if (image_kind != 7 && image_kind != 8 && image_kind != 9) return;
    static const char *const hashes[3] = {
        "d8fa2c4590a6b0c16b4b481270f121bb4f06f58c7c3dc47051a82ba3b6845f0c",
        "48caebb0b3233ca9c3a0b4dbd71d74872b207ebc15ef73c22643b0fa444cfc73",
        "f579190bb2c0922ef023b8e1a83d0a4f8a38193f886ffbeaa95aa32a8117204c"
    };
    static const size_t expected[3] = {5030,28233,80566};
    *hash = hashes[index]; *size = expected[index];
    if (image_kind == 8 && index == 0) {
        *hash = "b2c4361cb6fb8566cde5b09e83f2ee0b5e274151f3de6602815b9054fc28c25c";
        *size = 7368;
    }
    if (image_kind == 9) {
        static const char *const protected_hashes[3]={
            "addfe98643e0a0660be955285cf375aae8597cf70e5c2f92788c720a78f13639",
            "48caebb0b3233ca9c3a0b4dbd71d74872b207ebc15ef73c22643b0fa444cfc73",
            "357e0014fdb77d99033a5f251054e63187e651c830f27073ae0b4ed57e43b3da"};
        static const size_t protected_sizes[3]={15372,28233,91141};
        *hash=protected_hashes[index];*size=protected_sizes[index];
    }
}
static bool gia_capture_load_inputs(const char *inputs, unsigned image_kind, uint8_t *data[3], size_t sizes[3])
{
    static const char *const names[3] = {
        "provenance-output.sha256", "license-COPYRIGHT", "source-before.patch"
    };
    static const char *const hashes[3] = {
        "90a9f9a5990af9c99ca93938c7daa9b6e4753d931c8b4a68232ba2b4c7fe1944",
        "4bb0fdcd07d8a7774ba71faecf86d7db64d7a8574ee395f51a86d629c39f77cc",
        "d1b7a3e3e074e70d20bcb894e12ae177e9d218470f1a6e5644a77413dfea5ab0"
    };
    static const size_t expected[3] = {1010, 6070, 35875};
    static const char *const v7_hashes[3] = {
        "8bc142a918bd385d107c902bf6838e093226c6bfadcfd722030208900ee00232",
        "4bb0fdcd07d8a7774ba71faecf86d7db64d7a8574ee395f51a86d629c39f77cc",
        "938e88112733c9eb0accc25cc509eb927a8393623b326592c9f7deded8802dfe"
    };
    static const size_t v7_expected[3] = {2949, 6070, 53739};
    static const char v2_provenance[] =
        "3ff6d8dfe7b91d5b0b14adb0b04887e2066dcffc719c35a2c069afdc4df101d6";
    static const char v5_provenance[] =
        "e36fcbe987004d65f362c23dfbaf789fcfaec1228b43c704d9a63f3998f917c2";
    static const char v6_provenance[] =
        "c756d03c0276cdc31651cf9c7ba2009972e341c323ea3b3162d00e6e39196ddd";
    bool ok = true;
    for (size_t i = 0; i < 3 && ok; ++i) {
        const char *hash = hashes[i];
        if (i == 0 && image_kind == 1) hash = v2_provenance;
        if (i == 0 && image_kind == 2) hash = v5_provenance;
        if (i == 0 && image_kind == 3) hash = v6_provenance;
        size_t size = image_kind != 0 && i == 0 ? 807 : expected[i];
        if (image_kind >= 4 && image_kind <= 6) { hash = v7_hashes[i]; size = v7_expected[i]; }
        gia_capture_paired_provenance(image_kind, i, &hash, &size);
        gia_capture_combined_metadata(image_kind, i, &hash, &size);
        ok = gia_capture_input(inputs, names[i], hash, size, &data[i], &sizes[i]);
    }
    return ok;
}
static bool gia_capture_inputs(const char *repo, unsigned image_kind, uint8_t *data[3], size_t sizes[3])
{
    char parent[768], inputs[800];
    size_t n = strlen(repo);
    if (!n || n >= sizeof(parent)) return false;
    memcpy(parent, repo, n + 1);
    char *slash = strrchr(parent, '/');
    if (!slash || !slash[1]) return false;
    *slash = 0;
    int len = snprintf(inputs, sizeof(inputs), "%s/capture-inputs", parent);
    if (len < 0 || (size_t)len >= sizeof(inputs)) return false;
    uintptr_t parent_fd, inputs_fd;
    if (!platform_private_directory_open_validated(parent, &parent_fd)) return false;
    bool ok = platform_private_directory_open_validated(inputs, &inputs_fd);
    if (ok) {
        ok = gia_capture_load_inputs(inputs, image_kind, data, sizes);
        platform_private_directory_close(inputs_fd);
    }
    platform_private_directory_close(parent_fd);
    return ok;
}
static bool gia_capture_stage(const char *repo, const uint8_t *image, size_t bytes,
                              uint8_t *data[3], const size_t sizes[3],
                              struct vcs_guest_image_observation *o, uint8_t root[32])
{
    memset(o, 0, sizeof(*o));
    if (!platform_private_directory_create(repo) || !vcs_object_store_init(repo)) return false;
    o->image.bytes = bytes;
    gia_test_sha(image, bytes, o->image_sha256);
    if (!vcs_object_put(repo, image, bytes, VCS_TAG_BLOB, o->image.root)) return false;
    for (size_t i = 0; i < 3; ++i) {
        o->evidence[i].bytes = sizes[i];
        if (!vcs_object_put(repo, data[i], sizes[i], VCS_TAG_BLOB, o->evidence[i].root)) return false;
    }
    uint8_t wire[VCS_GUEST_IMAGE_WIRE_BYTES];
    return vcs_guest_image_observation_encode(o, wire) &&
           vcs_object_put(repo, wire, sizeof(wire), VCS_TAG_BLOB, root);
}
static bool gia_capture_allowed(const uint8_t *image, size_t bytes,
                                struct gia_test_policy *policy, unsigned *image_kind)
{
    static const char *const digests[] = {
        public_digest, public_v2_digest, public_v5_digest, public_v6_digest, public_v7_digest,
        "fca910590d9b3171712883285fb30743b30f7715a4b8fb41c17a51bfdcca6a6e",
        "c7df418c75c63125a6ea77edba7b654486c5912bc1fd60c53fcc39778dbb1bf7",
        "82d6598d9669339eb9890d9c8b5152597beac22cbfc5c86200a23f1dc2cd3562",
        "f7e7379fb08fd0035cf67bd98d5896376e103ab80851363d2c1f1a16a53e675d",
        "a5080bb076351c5b5e058a81e5bf6ad3a0f748e97423d2214af5602a5f90097c"
    };
    uint8_t actual[32];
    gia_test_sha(image, bytes, actual);
    *image_kind = 0;
    memcpy(policy->digest, actual, 32);
    static const size_t lengths[] = {43407928,43407928,43407928,43407928,43407928,43408024,43406744,43412608,43412608,43412608};
    for (unsigned i = 0; i < sizeof digests / sizeof digests[0]; i++) {
        uint8_t expected[32];
        if (!zcl_hex_decode(digests[i], expected, 32)) return false;
        if (bytes == lengths[i] && !memcmp(actual, expected, 32)) { *image_kind = i; return true; }
    }
    return false;
}
static bool gia_capture(const char *repo, const uint8_t *image, size_t bytes)
{
    uint8_t *data[3] = {0}; size_t sizes[3] = {0};
    struct vcs_guest_image_observation o;
    struct gia_test_policy policy = {.enabled = true};
    struct guest_image_admission *h = NULL;
    unsigned image_kind = 0;
    bool allowed = gia_capture_allowed(image, bytes, &policy, &image_kind);
    bool ok = allowed && gia_capture_inputs(repo, image_kind, data, sizes) &&
              gia_capture_stage(repo, image, bytes, data, sizes, &o, policy.root);
    if (ok) {
        uint64_t budget = VCS_GUEST_IMAGE_WIRE_BYTES + bytes;
        for (size_t i = 0; i < 3; ++i) budget += sizes[i];
        const uint8_t *copy = NULL; size_t copied = 0;
        ok = guest_image_admission_open(repo, policy.root, bytes, budget,
                                       gia_test_grant, &policy, &h).ok &&
             guest_image_admission_bytes(h, &copy, &copied).ok &&
             copied == bytes && memcmp(copy, image, bytes) == 0 &&
             guest_image_admission_current(h).ok;
        if (ok) {
            char root_hex[65]; zcl_hex_encode(policy.root, 32, root_hex);
            printf("PUBLIC_CAPTURE COPIED_BYTES_ONLY root=%s repo=%s\n", root_hex, repo);
        }
    }
    guest_image_admission_close(&h);
    for (size_t i = 0; i < 3; ++i) free(data[i]);
    return ok;
}

/* Normal adapter controls remain the original2445 fixture. Alternate capture
 * accepts only the fixed observed image tuples, never arbitrary SHA. */
static bool gia_capture_selected(const char *repo, const uint8_t *image, size_t bytes)
{
    const char *path = getenv("ZCL_TEST_GUEST_IMAGE_CAPTURE_KERNEL");
    if (!path) return gia_capture(repo, image, bytes);
    uint8_t *selected = NULL; size_t selected_bytes = 0;
    if (!gia_test_load(path, VCS_GUEST_IMAGE_MAX_BYTES, &selected, &selected_bytes))
        return false;
    bool ok = gia_capture(repo, selected, selected_bytes);
    free(selected);
    return ok;
}
static int gia_combined_metadata_controls(void)
{
    int failures=0;
    TEST("combined capture pins all three independently distinct evidence inputs") {
        static const char *const expected[]={
            "d8fa2c4590a6b0c16b4b481270f121bb4f06f58c7c3dc47051a82ba3b6845f0c",
            "48caebb0b3233ca9c3a0b4dbd71d74872b207ebc15ef73c22643b0fa444cfc73",
            "f579190bb2c0922ef023b8e1a83d0a4f8a38193f886ffbeaa95aa32a8117204c"
        };
        static const size_t lengths[]={5030,28233,80566};
        for(size_t i=0;i<3;i++) {
            const char *hash="unchanged";size_t size=1;
            gia_capture_combined_metadata(7,i,&hash,&size);
            ASSERT(strcmp(hash,expected[i])==0);ASSERT_EQ(size,lengths[i]);
            gia_capture_combined_metadata(8,i,&hash,&size);
            ASSERT(strcmp(hash,i ? expected[i] :
                "b2c4361cb6fb8566cde5b09e83f2ee0b5e274151f3de6602815b9054fc28c25c")==0);
            ASSERT_EQ(size,i ? lengths[i] : 7368u);
            hash="unchanged";size=1;gia_capture_combined_metadata(6,i,&hash,&size);
            ASSERT(strcmp(hash,"unchanged")==0);ASSERT_EQ(size,1u);
        }
        PASS();
    } _test_next:;
    return failures;
}
static int gia_evidence_refusal_controls(void)
{
    int failures=0;char dir[768],path[900];
    test_make_tmpdir(dir,sizeof dir,"guest_image_admission","combined-evidence");
    TEST("each capture evidence loader rejects wrong hash and wrong length") {
        static const char *const names[]={"provenance-output.sha256","license-COPYRIGHT","source-before.patch"};
        const uint8_t payload[]={1,2,3};uint8_t digest[32];char hash[65];
        gia_test_sha(payload,sizeof payload,digest);zcl_hex_encode(digest,32,hash);
        for(size_t i=0;i<3;i++) {
            int n=snprintf(path,sizeof path,"%s/%s",dir,names[i]);ASSERT(n>0&&(size_t)n<sizeof path);
            FILE *file=fopen(path,"wb");ASSERT(file!=NULL);
            size_t written=fwrite(payload,1,sizeof payload,file);int closed=fclose(file);
            ASSERT_EQ(written,sizeof payload);ASSERT_EQ(closed,0);
            uint8_t *data=NULL;size_t size=0;
            ASSERT(gia_capture_input(dir,names[i],hash,sizeof payload,&data,&size));free(data);data=NULL;
            char wrong[65];memcpy(wrong,hash,sizeof wrong);wrong[0]=wrong[0]=='0'?'1':'0';
            ASSERT(!gia_capture_input(dir,names[i],wrong,sizeof payload,&data,&size));free(data);data=NULL;
            ASSERT(!gia_capture_input(dir,names[i],hash,sizeof payload+1,&data,&size));free(data);
        }
        PASS();
    } _test_next:;
    return failures;
}
int test_guest_image_admission(void)
{
    int failures = gia_codec_controls();
    failures += gia_combined_metadata_controls() + gia_evidence_refusal_controls();
    const char *path = getenv("ZCL_TEST_PUBLIC_GUEST_IMAGE_KERNEL");
    uint8_t *image = NULL; size_t bytes = 0;
    if (!path || !*path) {
        /* The runner counts this "UNOBSERVED (" line; the controls above ran
         * and are hard-asserted, so an absent fixture is not a FAIL. */
        printf("UNOBSERVED (PUBLIC2445 copied image unavailable: "
               "ZCL_TEST_PUBLIC_GUEST_IMAGE_KERNEL unset)\n");
        return failures;
    }
    if (!gia_test_load(path, VCS_GUEST_IMAGE_MAX_BYTES, &image, &bytes)) {
        printf("FAIL (PUBLIC2445 copied image named by the environment cannot be read)\n");
        return failures + 1;
    }
    struct gia_test_policy policy = {.enabled = true};
    uint8_t digest[32]; gia_test_sha(image, bytes, digest);
    if (!zcl_hex_decode(public_digest, policy.digest, 32) ||
        memcmp(digest, policy.digest, 32) != 0) {
        free(image);
        printf("UNOBSERVED: fixture is not exact PUBLIC2445\n");
        return failures + 1;
    }
    char repo[768]; test_make_tmpdir(repo, sizeof(repo), "guest_image_admission", "cas");
    struct vcs_guest_image_observation observation;
    bool staged = gia_test_stage(repo, image, bytes, &observation, policy.root);
    if (!staged) {
        free(image);
        printf("UNOBSERVED: isolated PUBLIC copied CAS staging refused\n");
        test_rm_rf_recursive(repo);
        return failures + 1;
    }
    failures += gia_adapter_controls(repo, &observation, &policy);
    failures += gia_corrupt_controls(repo, &observation, &policy, image, bytes);
    const char *capture = getenv("ZCL_TEST_GUEST_IMAGE_CAPTURE_REPO");
    if (capture && !failures && !gia_capture_selected(capture, image, bytes)) {
        printf("UNOBSERVED: retained PUBLIC capture refused; partial destination preserved\n");
        ++failures;
    }
    free(image);
    test_rm_rf_recursive(repo);
    return failures;
}
