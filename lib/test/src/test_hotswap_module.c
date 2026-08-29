/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the REAL (activatable) Tier-1 hot-swap module ABI + the
 * command-registry epoch/refcount drain that makes dlclose-after-swap safe.
 *
 * _GNU_SOURCE is required before sys/mman.h so glibc exposes MAP_ANONYMOUS
 * under strict feature-test builds (-D_POSIX_C_SOURCE).
 *
 * The test binary compiles ONE translation unit — the loader,
 * lib/hotswap/src/hotswap_activate.c — with -DZCL_DEV_BUILD, so `make
 * t-hotswap` can run a real test group against a hot-swapped module through
 * the same loader the dev node runs. Every other TU stays release-shaped. The
 * refusals asserted below are therefore the REAL loader's prechecks (path
 * confinement, dev-datadir classification), not a release stub.
 *
 * The behaviours the dlopen path would exercise (ABI-version mismatch,
 * missing/incomplete fields, the swappable allowlist hard line, and a failing
 * module self_test) are all factored into the pure, always-compiled
 * hotswap_module_admit(), which is unit-tested here with fabricated modules —
 * no dlopen required. The live swap + epoch-quiesce drain is proven against
 * the real command-registry override layer with function-pointer handlers
 * (the same mechanism hotswap_activate's commit_cb publishes into). */

#define _GNU_SOURCE

#include "test/test_core.h"

#include "hotswap/hotswap.h"
#include "hotswap/hotswap_module.h"
#include "kernel/command_registry.h"
#include "json/json.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── Fabricated-module fixtures for hotswap_module_admit ──────────────── */

static void mod_handler(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply)
{
    (void)request;
    (void)json_push_kv_str(&reply->data, "who", "module");
}

static bool selftest_true(char *err, size_t cap) { (void)err; (void)cap; return true; }
static bool selftest_false(char *err, size_t cap)
{
    if (err && cap) snprintf(err, cap, "synthetic self_test failure");
    return false;
}

/* The status controller row of config/hotswap_swappable.def, whose declared
 * probe leaf in config/hotswap_eligible.def is core.status. */
#define STATUS_TU "app/controllers/src/status_native_handlers.c"

static const struct zcl_hotswap_leaf k_status_leaves[] = {
    { "core.status", mod_handler },
};
static const struct zcl_hotswap_leaf k_status_leaves_nullfn[] = {
    { "core.status", NULL },
};
static const struct zcl_hotswap_leaf k_consensus_leaves[] = {
    { "core.consensus.pow.verify", mod_handler },
};

static int test_admit_ok(void)
{
    int failures = 0;
    TEST("hotswap_module_admit accepts a well-formed allowlisted module") {
        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
            .core_sections = hotswap_core_sections_self(),
            .source_tu = STATUS_TU,   /* on config/hotswap_swappable.def */
            .leaf_count = 1,
            .leaves = k_status_leaves,
            .self_test = selftest_true,
        };
        char stage[64], why[192];
        ASSERT(hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        PASS();
    } _test_next:;
    return failures;
}

static int test_admit_abi_mismatch(void)
{
    int failures = 0;
    TEST("ABI version mismatch is refused at stage=abi") {
        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V2 + 7u,
            .source_tu = STATUS_TU, .leaf_count = 1,
            .leaves = k_status_leaves, .self_test = selftest_true,
        };
        char stage[64] = {0}, why[192] = {0};
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "abi"), 0);
        ASSERT(strstr(why, "abi_version") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_admit_missing_fields(void)
{
    int failures = 0;
    TEST("missing fields (NULL leaf fn) refused at stage=fields") {
        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
            .core_sections = hotswap_core_sections_self(),
            .source_tu = STATUS_TU, .leaf_count = 1,
            .leaves = k_status_leaves_nullfn, .self_test = selftest_true,
        };
        char stage[64] = {0}, why[192] = {0};
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "fields"), 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_admit_allowlist(void)
{
    int failures = 0;
    TEST("a non-allowlisted source is refused at stage=allowlist (HARD LINE)") {
        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
            .core_sections = hotswap_core_sections_self(),
            /* A consensus/validation TU — must NEVER be swappable. */
            .source_tu = "lib/consensus/src/pow.c",
            .leaf_count = 1, .leaves = k_consensus_leaves,
            .self_test = selftest_true,
        };
        char stage[64] = {0}, why[192] = {0};
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "allowlist"), 0);
        ASSERT(strstr(why, "allowlist") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_admit_leaf_not_owned(void)
{
    int failures = 0;
    TEST("an allowlisted source claiming a leaf it does not own is refused") {
        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
            .core_sections = hotswap_core_sections_self(),
            .source_tu = STATUS_TU, .leaf_count = 1,
            .leaves = k_consensus_leaves, .self_test = selftest_true,
        };
        char stage[64] = {0}, why[192] = {0};
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "allowlist"), 0);
        ASSERT(strstr(why, "core.consensus.pow.verify") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_admit_selftest_fail(void)
{
    int failures = 0;
    TEST("a failing module self_test is refused at stage=self_test (rollback)") {
        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
            .core_sections = hotswap_core_sections_self(),
            .source_tu = STATUS_TU, .leaf_count = 1,
            .leaves = k_status_leaves, .self_test = selftest_false,
        };
        char stage[64] = {0}, why[192] = {0};
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "self_test"), 0);
        ASSERT(strstr(why, "synthetic") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── The sealed-core SECTION declaration (ABI v3) ──────────────────────────
 *
 * A module records WHICH sealed sections it compiled against, and admission
 * verifies them IN ADDITION to the unchanged ROOT pin. Every case below is a
 * REFUSAL that did not exist before; none of them makes anything admissible.
 *
 * The fixtures start from the resident's own table and mutate ONE thing, so a
 * green result cannot come from the fixture being wrong in some other way. */

/* A narrowed declaration: the sections a status-controller module actually
 * reaches. Built at runtime from the resident table so it can never go stale
 * against a re-cut seal. */
#define SECT_MAX 64
struct sect_fixture {
    struct zcl_hotswap_core_section rows[SECT_MAX];
    struct zcl_hotswap_core_sections decl;
};

/* Copy the resident's whole declaration into a mutable fixture. */
static void sect_fixture_init(struct sect_fixture *f)
{
    const struct zcl_hotswap_core_sections *self = hotswap_core_sections_self();
    uint32_t n = self->count < SECT_MAX ? self->count : SECT_MAX;
    for (uint32_t i = 0; i < n; i++)
        f->rows[i] = self->sections[i];
    f->decl.tree = self->tree;
    f->decl.count = n;
    f->decl.sections = f->rows;
}

static struct zcl_hotswap_module sect_module(
    const struct zcl_hotswap_core_sections *decl)
{
    struct zcl_hotswap_module m = {
        .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
        .core_sections = decl,
        .source_tu = STATUS_TU,
        .leaf_count = 1,
        .leaves = k_status_leaves,
        .self_test = selftest_true,
    };
    return m;
}

static int test_sections_full_declaration_admitted(void)
{
    int failures = 0;
    TEST("sections: a module declaring every resident section is admitted") {
        struct sect_fixture f;
        sect_fixture_init(&f);
        ASSERT_EQ((int)f.decl.count, (int)ZCL_CORE_SEAL_SECTION_COUNT);
        struct zcl_hotswap_module m = sect_module(&f.decl);
        char stage[64] = {0}, why[256] = {0};
        ASSERT(hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        PASS();
    } _test_next:;
    return failures;
}

static int test_sections_narrowed_declaration_admitted(void)
{
    int failures = 0;
    TEST("sections: a NARROWED declaration (a real compile closure) is "
         "admitted") {
        /* Exactly what the build derives for a controller that reaches only
         * core/chainparams/include/chain — the one sealed header the whole
         * module set has in common. */
        static const char *const want[] = {
            "core/chainparams/include/chain",
        };
        struct sect_fixture f;
        f.decl.tree = hotswap_core_seal_tree();
        f.decl.count = 0;
        f.decl.sections = f.rows;
        for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
            const char *d = hotswap_core_section_digest(want[i]);
            ASSERT(d != NULL);
            f.rows[f.decl.count].path = want[i];
            f.rows[f.decl.count].digest = d;
            f.decl.count++;
        }
        struct zcl_hotswap_module m = sect_module(&f.decl);
        char stage[64] = {0}, why[256] = {0};
        ASSERT(hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        PASS();
    } _test_next:;
    return failures;
}

static int test_sections_wrong_digest_refused(void)
{
    int failures = 0;
    TEST("sections: a WRONG section digest is refused at stage=sections") {
        struct sect_fixture f;
        sect_fixture_init(&f);
        /* One byte of one row. Everything else — ROOT, TREE, the other 22
         * rows, every leaf — is exactly what the resident has. */
        static char bad[65];
        snprintf(bad, sizeof(bad), "%s", f.rows[0].digest);
        bad[63] = (bad[63] == 'a') ? 'b' : 'a';
        const char *mutated_path = f.rows[0].path;
        f.rows[0].digest = bad;

        struct zcl_hotswap_module m = sect_module(&f.decl);
        char stage[64] = {0}, why[256] = {0};
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "sections"), 0);
        ASSERT(strstr(why, mutated_path) != NULL);
        ASSERT(strstr(why, "mismatch") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sections_unknown_section_refused(void)
{
    int failures = 0;
    TEST("sections: a section this resident does not have is REFUSED, not "
         "ignored") {
        struct sect_fixture f;
        sect_fixture_init(&f);
        /* A module built from a tree where core/ had grown a directory this
         * resident's sealed core has never heard of. */
        ASSERT(hotswap_core_section_digest("core/futurework") == NULL);
        f.rows[f.decl.count].path = "core/futurework";
        f.rows[f.decl.count].digest =
            "0000000000000000000000000000000000000000000000000000000000000000";
        f.decl.count++;

        struct zcl_hotswap_module m = sect_module(&f.decl);
        char stage[64] = {0}, why[256] = {0};
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "sections"), 0);
        ASSERT(strstr(why, "core/futurework") != NULL);
        ASSERT(strstr(why, "does not have") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sections_tree_mismatch_refused(void)
{
    int failures = 0;
    TEST("sections: a TREE mismatch is refused even when every SECTION row "
         "matches") {
        struct sect_fixture f;
        sect_fixture_init(&f);
        static char bad_tree[65];
        snprintf(bad_tree, sizeof(bad_tree), "%s", hotswap_core_seal_tree());
        bad_tree[0] = (bad_tree[0] == 'a') ? 'b' : 'a';
        f.decl.tree = bad_tree;

        struct zcl_hotswap_module m = sect_module(&f.decl);
        char stage[64] = {0}, why[256] = {0};
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "sections"), 0);
        ASSERT(strstr(why, "TREE") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sections_absent_declaration_refused(void)
{
    int failures = 0;
    TEST("sections: a module declaring NO sections is refused — absence is "
         "what a pre-v3 artifact looks like") {
        struct zcl_hotswap_module m = sect_module(NULL);
        char stage[64] = {0}, why[256] = {0};
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "sections"), 0);
        ASSERT(strstr(why, "no sealed-core sections") != NULL);

        /* An empty-but-present declaration is the same refusal. */
        struct sect_fixture f;
        sect_fixture_init(&f);
        f.decl.count = 0;
        struct zcl_hotswap_module e = sect_module(&f.decl);
        stage[0] = why[0] = '\0';
        ASSERT(!hotswap_module_admit(&e, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "sections"), 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sections_duplicate_row_refused(void)
{
    int failures = 0;
    TEST("sections: the same section declared twice is refused (a duplicate "
         "could hide a mismatched second row)") {
        struct sect_fixture f;
        sect_fixture_init(&f);
        f.rows[f.decl.count] = f.rows[0];
        f.decl.count++;

        struct zcl_hotswap_module m = sect_module(&f.decl);
        char stage[64] = {0}, why[256] = {0};
        ASSERT(!hotswap_module_admit(&m, stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "sections"), 0);
        ASSERT(strstr(why, "twice") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* The v2 struct layout, verbatim: everything ABI v2 had, and nothing v3 added.
 * Used to prove a retired-ABI artifact is refused WITHOUT its trailing bytes
 * ever being read. */
struct v2_module_layout {
    uint32_t abi_version;
    const char *source_tu;
    uint32_t leaf_count;
    const struct zcl_hotswap_leaf *leaves;
    bool (*self_test)(char *err, size_t cap);
};

static int test_sections_old_abi_refused_without_overread(void)
{
    int failures = 0;
    TEST("abi: a v2 module is refused at stage=abi WITHOUT reading past the "
         "v2 layout (proved with a guard page)") {
        /* v3 is strictly longer, so there IS something past a v2 object. */
        ASSERT(sizeof(struct zcl_hotswap_module) > sizeof(struct v2_module_layout));

        long page = sysconf(_SC_PAGESIZE);
        ASSERT(page > 0);
        unsigned char *region = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        ASSERT(region != MAP_FAILED);
        /* Second page unreadable: any read past the v2 object faults. */
        ASSERT_EQ(mprotect(region + page, (size_t)page, PROT_NONE), 0);

        size_t off = (size_t)page - sizeof(struct v2_module_layout);
        off &= ~(size_t)(_Alignof(struct v2_module_layout) - 1);
        struct v2_module_layout *v2 =
            (struct v2_module_layout *)(void *)(region + off);
        v2->abi_version = ZCL_HOTSWAP_MODULE_ABI_V2;
        v2->source_tu = STATUS_TU;
        v2->leaf_count = 1;
        v2->leaves = k_status_leaves;
        v2->self_test = selftest_true;

        char stage[64] = {0}, why[256] = {0};
        /* If admit read core_sections it would touch the guard page and die. */
        ASSERT(!hotswap_module_admit((const struct zcl_hotswap_module *)(void *)v2,
                                     stage, sizeof(stage), why, sizeof(why)));
        ASSERT_EQ(strcmp(stage, "abi"), 0);
        ASSERT(strstr(why, "abi_version") != NULL);
        ASSERT(strstr(why, "rebuild") != NULL);

        ASSERT_EQ(munmap(region, (size_t)page * 2), 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The compiled section table is a MIRROR of core/MANIFEST.sha3. Nothing in the
 * build forces it to be current, so re-derive it here from the manifest and
 * demand exact agreement. A seal re-cut that lands without
 * `make core-seal-sections` fails this case instead of silently leaving every
 * module declaring the OLD section digests.
 *
 * Read relative to the repo root, the directory the test binaries run from. */
static int test_sections_mirror_matches_manifest(void)
{
    int failures = 0;
    TEST("sections: the compiled table matches core/MANIFEST.sha3 exactly") {
        FILE *f = fopen("core/MANIFEST.sha3", "r");
        ASSERT(f != NULL);
        const struct zcl_hotswap_core_sections *self =
            hotswap_core_sections_self();
        char line[1024];
        char tree[128] = {0};
        uint32_t seen = 0;
        bool bad_row = false;
        while (fgets(line, sizeof(line), f)) {
            size_t len = strlen(line);
            while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
                line[--len] = '\0';
            if (strncmp(line, "TREE ", 5) == 0) {
                const char *p = line + 5;
                while (*p == ' ') p++;
                snprintf(tree, sizeof(tree), "%s", p);
                continue;
            }
            if (strncmp(line, "SECTION ", 8) != 0)
                continue;
            /* SECTION  <files>  <pathlen>  <hex>  <path> */
            unsigned files = 0, pathlen = 0;
            char hex[128] = {0};
            int consumed = 0;
            if (sscanf(line, "SECTION %u %u %127s %n", &files, &pathlen, hex,
                       &consumed) != 3 || consumed <= 0) {
                bad_row = true;
                break;
            }
            (void)files;
            const char *path = line + consumed;
            if (strlen(path) != pathlen) { bad_row = true; break; }
            if (seen >= self->count) { bad_row = true; break; }
            if (strcmp(self->sections[seen].path, path) != 0 ||
                strcmp(self->sections[seen].digest, hex) != 0) {
                printf("\n  drift at row %u: compiled %s=%s manifest %s=%s\n",
                       seen, self->sections[seen].path,
                       self->sections[seen].digest, path, hex);
                bad_row = true;
                break;
            }
            seen++;
        }
        fclose(f);
        ASSERT(!bad_row);
        /* Same count, same order, same TREE — regenerate with
         * `make core-seal-sections` if this fails. */
        ASSERT_EQ((int)seen, (int)self->count);
        ASSERT_EQ(strcmp(tree, self->tree), 0);
        ASSERT_EQ(strcmp(self->tree, hotswap_core_seal_tree()), 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sections_table_is_well_formed(void)
{
    int failures = 0;
    TEST("sections: the resident table is sorted, unique and 64-hex") {
        const struct zcl_hotswap_core_sections *self =
            hotswap_core_sections_self();
        ASSERT(self->count > 0);
        ASSERT_EQ((int)strlen(self->tree), 64);
        for (uint32_t i = 0; i < self->count; i++) {
            ASSERT(self->sections[i].path != NULL);
            ASSERT(self->sections[i].path[0] != '\0');
            ASSERT_EQ((int)strlen(self->sections[i].digest), 64);
            for (const char *p = self->sections[i].digest; *p; p++)
                ASSERT((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'));
            if (i)
                ASSERT(strcmp(self->sections[i - 1].path,
                              self->sections[i].path) < 0);
            /* Round-trips through the lookup admission uses. */
            ASSERT_EQ(strcmp(hotswap_core_section_digest(self->sections[i].path),
                             self->sections[i].digest), 0);
        }
        ASSERT(hotswap_core_section_digest("core/nope") == NULL);
        ASSERT(hotswap_core_section_digest("") == NULL);
        ASSERT(hotswap_core_section_digest(NULL) == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_module_sections(void)
{
    int failures = 0;
    failures += test_sections_table_is_well_formed();
    failures += test_sections_mirror_matches_manifest();
    failures += test_sections_full_declaration_admitted();
    failures += test_sections_narrowed_declaration_admitted();
    failures += test_sections_wrong_digest_refused();
    failures += test_sections_unknown_section_refused();
    failures += test_sections_tree_mismatch_refused();
    failures += test_sections_absent_declaration_refused();
    failures += test_sections_duplicate_row_refused();
    failures += test_sections_old_abi_refused_without_overread();
    return failures;
}

static int test_module_admit(void)
{
    int failures = 0;
    failures += test_admit_ok();
    failures += test_admit_abi_mismatch();
    failures += test_admit_missing_fields();
    failures += test_admit_allowlist();
    failures += test_admit_leaf_not_owned();
    failures += test_admit_selftest_fail();
    return failures;
}

static int test_swappable_allowlist(void)
{
    int failures = 0;
    TEST("hotswap_handler_is_swappable: allowlisted yes, everything else no") {
        ASSERT(hotswap_handler_is_swappable("core.status"));
        ASSERT(hotswap_handler_is_swappable("ops.metrics"));
        ASSERT(!hotswap_handler_is_swappable("core.consensus.pow.verify"));
        ASSERT(!hotswap_handler_is_swappable("app.jobs.reducer.advance"));
        ASSERT(!hotswap_handler_is_swappable(""));
        ASSERT(!hotswap_handler_is_swappable(NULL));
        PASS();
    } _test_next:;
    return failures;
}

/* ── Activation gate: -hotswap-activate flag + env + non-canonical datadir ── */

static int test_activation_gate(void)
{
    int failures = 0;
    TEST("activation is refused unless flag + env + exact dev datadir") {
        char tmpl[] = "/tmp/zcl_hs_gate_XXXXXX";
        char *home = mkdtemp(tmpl);
        ASSERT(home != NULL);
        char devdir[512], canondir[512];
        snprintf(devdir, sizeof(devdir), "%s/.zclassic-c23-dev", home);
        snprintf(canondir, sizeof(canondir), "%s/.zclassic-c23", home);
        ASSERT_EQ(mkdir(devdir, 0700), 0);
        ASSERT_EQ(mkdir(canondir, 0700), 0);

        char *saved_home = getenv("HOME");
        char saved_home_copy[512] = {0};
        if (saved_home) snprintf(saved_home_copy, sizeof(saved_home_copy), "%s", saved_home);
        setenv("HOME", home, 1);
        unsetenv("ZCL_HOTSWAP_ACTIVATE");
        hotswap_set_activate_flag(false);

        char why[256];

        /* No flag => refused. */
        why[0] = '\0';
        ASSERT(!hotswap_activation_authorized(devdir, why, sizeof(why)));
        ASSERT(strstr(why, "-hotswap-activate") != NULL);

        /* Flag but no env => refused. */
        hotswap_set_activate_flag(true);
        why[0] = '\0';
        ASSERT(!hotswap_activation_authorized(devdir, why, sizeof(why)));
        ASSERT(strstr(why, "ZCL_HOTSWAP_ACTIVATE") != NULL);

        /* Flag + env but canonical datadir => refused LOUDLY. */
        setenv("ZCL_HOTSWAP_ACTIVATE", "1", 1);
        why[0] = '\0';
        ASSERT(!hotswap_activation_authorized(canondir, why, sizeof(why)));
        ASSERT(strstr(why, "canonical") != NULL);

        /* Flag + env + non-dev arbitrary datadir => refused. */
        why[0] = '\0';
        ASSERT(!hotswap_activation_authorized("/tmp", why, sizeof(why)));

        /* Flag + env + exact dev datadir => AUTHORIZED. */
        why[0] = '\0';
        ASSERT(hotswap_activation_authorized(devdir, why, sizeof(why)));

        /* Restore global process state for sibling groups. */
        hotswap_set_activate_flag(false);
        unsetenv("ZCL_HOTSWAP_ACTIVATE");
        if (saved_home_copy[0]) setenv("HOME", saved_home_copy, 1);
        else unsetenv("HOME");
        rmdir(devdir);
        rmdir(canondir);
        rmdir(home);
        PASS();
    } _test_next:;
    return failures;
}

/* The loader TU (lib/hotswap/src/hotswap_activate.c) is compiled into the test
 * binaries with -DZCL_DEV_BUILD — and ONLY that TU — so `make t-hotswap` can
 * run a test group against a hot-swapped module through the SAME loader the
 * dev node runs, instead of relinking the whole harness for a one-file edit.
 * See the module-mode block in the Makefile beside TEST_FAST_OBJECT_CFLAGS.
 *
 * Every OTHER TU stays release-shaped, so the "this binary is not a dev build"
 * assertions elsewhere in the suite remain true.
 *
 * What must stay proven here is that the REAL loader still refuses before it
 * touches anything: a path outside the confinement set never reaches dlopen,
 * and a non-dev datadir is refused ahead of the authorization gate. */
static int test_loader_refuses_unconfined_input(void)
{
    int failures = 0;
    TEST("the real loader refuses an unconfined so_path at precheck") {
        struct hotswap_activate_report report;
        /* Absolute, .so-suffixed, but neither /tmp nor build/hotswap, and
         * nonexistent — refused before dlopen, with nothing published. */
        bool ok = hotswap_activate("/nonexistent/module.so", "/tmp", true,
                                   NULL, &report);
        ASSERT(!ok);
        ASSERT(!report.ok);
        ASSERT(!report.activated);
        ASSERT_EQ(strcmp(report.stage, "precheck"), 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_loader_refuses_non_dev_datadir(void)
{
    int failures = 0;
    TEST("the real loader refuses a datadir that is not the dev lane") {
        struct hotswap_activate_report report;
        bool ok = hotswap_activate("/tmp/whatever.so", "/tmp", true, NULL,
                                   &report);
        ASSERT(!ok);
        ASSERT(!report.ok);
        ASSERT(!report.activated);
        /* Either gate may speak first depending on whether the path exists;
         * both are precheck refusals and both publish zero leaves. */
        ASSERT_EQ(strcmp(report.stage, "precheck"), 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Live swap + epoch-quiesce drain (registry override layer) ─────────── */

static _Atomic int g_v1_calls = 0;
static _Atomic int g_v2_calls = 0;

static void h_v1(const struct zcl_command_request *request,
                 struct zcl_command_reply *reply)
{
    (void)request;
    atomic_fetch_add_explicit(&g_v1_calls, 1, memory_order_relaxed);
    (void)json_push_kv_str(&reply->data, "v", "v1");
}
static void h_v2(const struct zcl_command_request *request,
                 struct zcl_command_reply *reply)
{
    (void)request;
    atomic_fetch_add_explicit(&g_v2_calls, 1, memory_order_relaxed);
    (void)json_push_kv_str(&reply->data, "v", "v2");
}

static const struct zcl_command_spec g_mod_specs[] = {
    {
        .path = "hs.mod.read",
        .summary = "swappable read leaf",
        .layer = ZCL_COMMAND_LAYER_CORE,
        .effect = ZCL_COMMAND_EFFECT_READ,
        .availability = ZCL_COMMAND_READY,
        .mode = ZCL_COMMAND_MODE_SYNC,
        .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
        .handler = h_v1,
    },
};
static const struct zcl_command_registry g_mod_reg = {
    .commands = g_mod_specs,
    .count = sizeof(g_mod_specs) / sizeof(g_mod_specs[0]),
};

static enum zcl_command_exit mod_exec(char *out, size_t out_size)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    enum zcl_command_exit ec = ZCL_COMMAND_EXIT_INTERNAL;
    (void)zcl_command_registry_execute_json(&g_mod_reg, &g_mod_specs[0], NULL,
                                            &input, false, "hs.mod.read",
                                            "normal", 0, 0, NULL, out, out_size,
                                            &ec);
    json_free(&input);
    return ec;
}

static int test_live_swap_and_quiesce(void)
{
    int failures = 0;
    TEST("commit swaps the live handler; retired snapshot quiesces when idle") {
        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(&g_mod_reg);
        atomic_store(&g_v1_calls, 0);
        atomic_store(&g_v2_calls, 0);
        char out[4096];

        /* Baseline builtin handler. */
        ASSERT_EQ((int)mod_exec(out, sizeof(out)), (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"v\":\"v1\"") != NULL);

        /* Publish v1 override (generation 1). */
        struct zcl_command_handler_override o1 = { .path = "hs.mod.read", .handler = h_v1 };
        char why[256] = {0};
        ASSERT(zcl_command_registry_replace_batch(0, &o1, 1, why,
                                                 sizeof(why), NULL));

        /* No in-flight readers: every retired snapshot has drained. */
        ASSERT(zcl_command_registry_all_retired_quiesced());

        /* Swap to v2 (generation 2, retires the gen-1 snapshot). */
        struct zcl_command_handler_override o2 = { .path = "hs.mod.read", .handler = h_v2 };
        ASSERT(zcl_command_registry_replace_batch(0, &o2, 1, why,
                                                 sizeof(why), NULL));
        ASSERT_EQ((int)mod_exec(out, sizeof(out)), (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"v\":\"v2\"") != NULL);
        ASSERT(atomic_load(&g_v2_calls) >= 1);

        /* With readers idle the retired gen-1 snapshot has quiesced — a loader
         * would now be clear to dlclose the superseded .so. */
        ASSERT(zcl_command_registry_all_retired_quiesced());

        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Concurrent dispatch during swap: never garbage, quiesces after join ── */

#define MOD_HAMMER_ITERS 4000
#define MOD_HAMMER_READERS 6

static _Atomic bool g_mod_done = false;
static _Atomic int g_mod_torn = 0;

static void *mod_writer(void *arg)
{
    (void)arg;
    struct zcl_command_handler_override ovr = { .path = "hs.mod.read", .handler = h_v1 };
    for (uint32_t i = 1; i <= MOD_HAMMER_ITERS; i++) {
        ovr.handler = (i & 1u) ? h_v2 : h_v1;
        (void)zcl_command_registry_replace_batch(i, &ovr, 1, NULL, 0, NULL);
    }
    atomic_store_explicit(&g_mod_done, true, memory_order_release);
    return NULL;
}

static void *mod_reader(void *arg)
{
    (void)arg;
    char out[4096];
    while (!atomic_load_explicit(&g_mod_done, memory_order_acquire)) {
        if (mod_exec(out, sizeof(out)) != ZCL_COMMAND_EXIT_OK) {
            atomic_fetch_add_explicit(&g_mod_torn, 1, memory_order_relaxed);
            continue;
        }
        /* Every landed call must be exactly v1 or v2 — never torn/garbage. */
        bool marker = strstr(out, "\"v\":\"v1\"") != NULL ||
                      strstr(out, "\"v\":\"v2\"") != NULL;
        struct json_value parsed;
        json_init(&parsed);
        bool parses = json_read(&parsed, out, strlen(out));
        json_free(&parsed);
        if (!marker || !parses)
            atomic_fetch_add_explicit(&g_mod_torn, 1, memory_order_relaxed);
    }
    return NULL;
}

static int test_concurrent_swap_hammer(void)
{
    int failures = 0;
    TEST("N readers dispatch while a writer swaps: no garbage, drains after") {
        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(&g_mod_reg);
        atomic_store(&g_mod_done, false);
        atomic_store(&g_mod_torn, 0);

        pthread_t writer;
        pthread_t readers[MOD_HAMMER_READERS];
        ASSERT_EQ(pthread_create(&writer, NULL, mod_writer, NULL), 0);
        for (int i = 0; i < MOD_HAMMER_READERS; i++)
            ASSERT_EQ(pthread_create(&readers[i], NULL, mod_reader, NULL), 0);
        pthread_join(writer, NULL);
        for (int i = 0; i < MOD_HAMMER_READERS; i++)
            pthread_join(readers[i], NULL);

        ASSERT_EQ(atomic_load(&g_mod_torn), 0);
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)MOD_HAMMER_ITERS);
        /* All readers gone: every retired snapshot must have drained to zero,
         * so the epoch/refcount drain terminates (dlclose would be safe). */
        ASSERT(zcl_command_registry_all_retired_quiesced());

        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_hotswap_module(void);

int test_hotswap_module(void)
{
    int failures = 0;
    failures += test_module_admit();
    failures += test_module_sections();
    failures += test_swappable_allowlist();
    failures += test_activation_gate();
    failures += test_loader_refuses_unconfined_input();
    failures += test_loader_refuses_non_dev_datadir();
    failures += test_live_swap_and_quiesce();
    failures += test_concurrent_swap_hammer();
    zcl_command_registry_reset_overrides();
    zcl_command_registry_set_active(NULL);
    printf("=== hotswap_module: %d failures ===\n", failures);
    return failures;
}
