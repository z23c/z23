/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The semantic_build_inputs cases for what make runs as it reads
 *          the makefiles: parse-time commands that write or name an
 *          include (widen), a conditional that provably skips a missing
 *          include (narrow, recorded with its premises), and the plan
 *          premise parse-commands-no-include-writes, recorded whenever an
 *          optional include is read while a parse-time command that is not
 *          provably read-only runs. */

#include "test/test_core.h"

#include "devloop_facts.h"
#include "test/semantic_build_inputs_fixture.h"

#include <stdio.h>
#include <string.h>

/* The name make reads the fixture's root makefile by. make tries GNUmakefile,
 * makefile, Makefile in order; a case-insensitive filesystem (macOS) opens the
 * fixture's Makefile as "makefile", so make and the facts reader both name it
 * so, and a rule remakes it only under that spelling. */
#if defined(__APPLE__)
#define SBI_ROOT_NAME "makefile"
#else
#define SBI_ROOT_NAME "Makefile"
#endif

/* A missing optional include no rule makes, read after a parse-time command. */
#define SBI_P_TAIL "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\n" SBI_GEN_RULE

/* D: a line make expands as it reads the makefiles runs a command that
 * writes a file (a $(shell) or != redirection or tee, a $(file >), each
 * also through $(call shell,...), or any function a $(call) names by a
 * computed name ($(call $(F)), $(call s$(H)ell)) or through $(call call)),
 * which may be an include make reads next, missing or not; or one
 * that names an optional include (a missing one's path, basename or
 * directory, an existing one's path or basename, or a variable whose value
 * names one), which may create or rewrite it. */
static int sbit_t_parse_time_writers(void)
{
    int failures = 0;
    static const struct sbi_case cases[] = {
        {"h09", "X := $(shell printf 'build/a.o: | gen\\n' > build/gen.mk)\n"
                "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\n"
                SBI_GEN_RULE, NULL, NULL},
        {"h12", "LATE = $(shell printf 'build/a.o: | gen\\n' > build/gen.mk)\n"
                "NOW := $(LATE)\n" SBI_GEN_INCLUDE("\t@: $(NOW)\n"), NULL, NULL},
        {"h13", "X != printf 'build/a.o: | gen\\n' > build/gen.mk\n"
                "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\n"
                SBI_GEN_RULE, NULL, NULL},
        {"h09_present", "X := $(shell printf 'build/a.o: | gen\\n' > build/gen.mk)\n"
                        "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\n"
                        SBI_GEN_RULE, "build/gen.mk", "# old\n"},
        {"h13_present", "X != printf 'build/a.o: | gen\\n' > build/gen.mk\n"
                        "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\n"
                        SBI_GEN_RULE, "build/gen.mk", "# old\n"},
        {"d_tee", "X := $(shell printf 'build/a.o: | gen\\n' | tee build/gen.mk)\n"
                  "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\n"
                  SBI_GEN_RULE, "build/gen.mk", "# old\n"},
        {"d_file", "$(file >build/gen.mk,build/a.o: | gen)\n"
                   "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\n"
                   SBI_GEN_RULE, "build/gen.mk", "# old\n"},
        {"d_subst_in_quotes", "X := $(shell printf '%s' \"$$(printf a)\" "
                              "> build/gen.mk)\nall: build/a.o\n" SBI_OBJ_RULE
                              "-include build/gen.mk\n" SBI_GEN_RULE,
         "build/gen.mk", "# old\n"},
        {"d_define", "define W\n$(shell printf 'build/a.o: | gen\\n' > build/gen.mk)\n"
                     "endef\nX := $(W)\n"
                     "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\n"
                     SBI_GEN_RULE, "build/gen.mk", "# old\n"},
        {"p01", "X := $(shell cp tools/t.txt build/gen.mk)\n" SBI_P_TAIL, NULL, NULL},
        {"p03", "X != ln -sf ../tools/t.txt build/gen.mk\n" SBI_P_TAIL, NULL, NULL},
        {"p01_var", "GEN := build/gen.mk\nCMD = cp t $(GEN)\nX := $(shell $(CMD))\n" SBI_P_TAIL, NULL, NULL},
        {"r01", "X := $(shell cp t $(addsuffix .mk,build/gen))\n" SBI_P_TAIL, NULL, NULL},
        {"r02", "X := $(shell cp t $(patsubst %.in,%.mk,build/gen.in))\n" SBI_P_TAIL, NULL, NULL},
        {"r03", "X := $(shell cp t $(subst Q,.,build/genQmk))\n" SBI_P_TAIL, NULL, NULL},
        {"r05", "X := $(shell cp tools/tpl/* build/)\n" SBI_P_TAIL, NULL, NULL},
        {"r06", "X := $(shell n=gen; cp t build/$$n.mk)\n" SBI_P_TAIL, NULL, NULL},
        {"r07", "A := gen\nB := .mk\nX := $(shell cp t build/$(A)$(B))\n" SBI_P_TAIL, NULL, NULL},
        {"r08", "X := $(shell cp t \"build/$$(printf g%sn e).mk\")\n" SBI_P_TAIL, NULL, NULL},
        {"r09", "X := $(shell cd tools/tpl && cp * ../../build/)\n" SBI_P_TAIL, NULL, NULL},
        {"r10", "X != cp -r tools/tpl/. build/\n" SBI_P_TAIL, NULL, NULL},
        {"u02", "X := $(call shell,cp tools/tpl.mk build/gen.mk)\n" SBI_P_TAIL, NULL, NULL},
        {"u04", "F := shell\nX := $(call $(F),cp tools/tpl.mk build/gen.mk)\n" SBI_P_TAIL,
         NULL, NULL},
        {"u15", "X := $(shell cp tools/tpl.mk build/gen.mk)\n" SBI_P_TAIL,
         "build/gen.mk", "# old\n"},
        {"a01", "X := $(call call,shell,tools/mkgen.sh)\n" SBI_P_TAIL, NULL, NULL},
        {"a02", "X := $(call call,shell,cp tools/tpl.mk build/gen.mk)\n" SBI_P_TAIL, NULL, NULL},
        {"a03", "H := h\nX := $(call s$(H)ell,cp tools/tpl.mk build/gen.mk)\n" SBI_P_TAIL,
         NULL, NULL},
        {"a03b", "H := h\nX := $(call s$(H)ell,tools/mkgen.sh)\n" SBI_P_TAIL, NULL, NULL},
    };
    TEST_CASE("semantic_build_inputs: a $(shell), != or $(file) that writes "
             "a file as make reads the makefiles widens") {
        ASSERT(sbi_cases_widen(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* A parse-time command that writes nothing (output to a descriptor or
 * /dev/null, a $(file <) read) leaves the build inputs as they were. */
static int sbit_t_parse_time_quiet(void)
{
    int failures = 0;
    static const char *const changed[] = {"tools/x.sh"};
    struct sbi_run r = {0};
    TEST_CASE("semantic_build_inputs: a parse-time command that writes no "
             "file narrows") {
        ASSERT(sbi_consume_with("sbi_parse_quiet",
                                "REV := $(shell git rev-parse HEAD 2>/dev/null)\n"
                                "N != git log -1 --oneline 2>&1 >&2\n"
                                "V := $(file <build/gen.mk)\n"
                                "K := $(shell printf '%s' '<root>' \"a>b\")\n"
                                "define LINK\nbuild/l.rsp:\n"
                                "\t@$$(file >$$@,x) test -s \"$$@\"\nendef\n"
                                "all: build/a.o\n" SBI_OBJ_RULE
                                "-include build/gen.mk\n" SBI_GEN_RULE,
                                "build/gen.mk", "# old\n", changed, 1, &r));
        ASSERT(sbi_narrowed(&r));
    } TEST_END
    zcl_devloop_facts_report_free(&r.rep);
    return failures;
}

/* ---- a conditional that provably skips a missing include ---------------------- */

/* The real Makefile's markers sit in conditionals: build/ready.mk, which
 * a rule makes, is included only in the branch `cond` opens (`post`
 * closes what `pre` opened). Skipped, it narrows; read, it widens. */
#define SBI_GUARD(pre, cond, post)                                             \
    pre cond "\n-include build/ready.mk\nendif\n" post                         \
    "build/ready.mk:\n\t@printf '%s\\n' '# ready' > $@\n" SBI_OBJ_RULE          \
    SBI_GEN_RULE
/* The epoch marker: leases only where an epoch holds .unverified. */
#define SBI_EPOCH                                                              \
    SBI_GUARD("BUILD_DIR = build\nOBJ_ROOT = $(BUILD_DIR)/obj\nZERO := 0000\n" \
              "define zcl_compile_epoch\n$(strip $(shell tools/key.sh $(1) "   \
              "2>/dev/null))\nendef\nPROFILES := build-only\n"                 \
              "ifneq ($(filter build-only,$(PROFILES)),)\n"                    \
              "EPOCH := $(call zcl_compile_epoch,b)\nelse\n"                   \
              "EPOCH := $(ZERO)\nendif\nOBJ_DIR = $(OBJ_ROOT)/epochs/$(EPOCH)\n" \
              "LEASES = \\\n\t$(if $(and $(filter build-only,$(PROFILES)),"     \
              "$(wildcard $(OBJ_DIR)/.unverified)),$(LEASE))\n"                 \
              "ifeq ($(strip $(MAKE_RESTARTS)),)\n",                           \
              "ifneq ($(strip $(LEASES)),)", "endif\n")
/* The tor and vendor markers: an archive the tree lacks, or a repair goal. */
#define SBI_MISSING(libs)                                                      \
    libs "MISSING := $(filter-out $(wildcard $(LIBS)),$(LIBS))\n"
#define SBI_TOR SBI_MISSING("TREE := vendor/tor\nLIBS := $(TREE)/libtor.a \\\n" \
                            "\t$(TREE)/libx.a\n")
#define SBI_VENDOR                                                             \
    "REPAIR_GOALS := vendor-ready deploy install\n"                            \
    "REPAIR := $(filter $(REPAIR_GOALS),$(MAKECMDGOALS))\n"                    \
    SBI_MISSING("LIBS := $(addprefix vendor/lib/,liba.a)\n")
#define SBI_LIBA "LIBS := vendor/lib/liba.a\n"
#define SBI_IF_UNAME "ifeq ($(shell uname),Linux)\n"
#define SBI_MISSING_COND "ifneq ($(strip $(MISSING)),)"

struct sbi_gcase {
    const char *id, *makefile;
    const char *const *files;
    bool narrow;
};

static const char *const k_sbi_tor[] = {"vendor/tor/libtor.a", "!\n",
                                        "vendor/tor/libx.a", "!\n", NULL};
static const char *const k_sbi_tor_one[] = {"vendor/tor/libtor.a", "!\n", NULL};
static const char *const k_sbi_liba[] = {"vendor/lib/liba.a", "!\n", NULL};
static const char *const k_sbi_libs[] = {"vendor/lib/liba.a", "!\n",
                                         "vendor/lib/libb.a", "!\n", NULL};
static const char *const k_sbi_unverified[] = {
    "build/obj/epochs/abc/.unverified", "", NULL};
static const char *const k_sbi_zero[] = {"build/obj/epochs/0000/.unverified",
                                         "", NULL};
static const char *const k_sbi_dot[] = {"d/.hidden", "", NULL};
static const char *const k_sbi_dotdir[] = {"d/.h/m", "", NULL};
static const char *const k_sbi_ds[] = {"d/s/f", "", NULL};
static const char *const k_sbi_dx[] = {"d/x", "", NULL};
static const char *const k_sbi_dab[] = {"d/b", "", "d/a", "", NULL};

/* Each case narrows or widens as it says; each that does not is named. */
static bool sbi_guard_cases(const struct sbi_gcase *cases, size_t n)
{
    static const char *const changed[] = {"tools/x.sh"};
    bool all = true;
    for (size_t k = 0; k < n; k++) {
        struct sbi_run r = {0};
        char tag[64];
        bool ok;
        (void)snprintf(tag, sizeof(tag), "sbi_guard_%s", cases[k].id);
        ok = sbi_consume_files(tag, cases[k].makefile, cases[k].files, changed,
                               1, &r) &&
             (cases[k].narrow ? sbi_narrowed(&r) : sbi_widened(&r));
        zcl_devloop_facts_report_free(&r.rep);
        if (!ok) {
            printf("[guard %s did not %s] ", cases[k].id,
                   cases[k].narrow ? "narrow" : "widen");
            all = false;
        }
    }
    return all;
}

static int sbit_t_guarded_include(void)
{
    int failures = 0;
    static const struct sbi_gcase cases[] = {
        {"epoch", SBI_EPOCH, NULL, true},
        {"epoch_unverified", SBI_EPOCH, k_sbi_unverified, false},
        {"epoch_zero", SBI_EPOCH, k_sbi_zero, false},
        {"tor", SBI_GUARD(SBI_TOR, SBI_MISSING_COND, ""), k_sbi_tor, true},
        {"tor_missing", SBI_GUARD(SBI_TOR, SBI_MISSING_COND, ""), k_sbi_tor_one,
         false},
        {"vendor", SBI_GUARD(SBI_VENDOR, "ifneq ($(strip $(MISSING) $(REPAIR)),)",
                             ""), k_sbi_liba, true},
        {"vendor_missing", SBI_GUARD(SBI_VENDOR, "ifneq ($(strip $(MISSING) "
                                     "$(REPAIR)),)", ""), NULL, false},
        {"vendor_ready_goal", SBI_GUARD("", "ifeq ($(MAKECMDGOALS),vendor-ready)",
                                        ""), NULL, false},
        {"vendor_other_goal", SBI_GUARD("", "ifneq ($(filter vendor-ready all,"
                                        "$(MAKECMDGOALS)),)", ""), NULL, false},
        {"view", SBI_GUARD("CLEAN := 1\n", "ifneq ($(CLEAN),1)", ""), NULL, true},
        {"view_goal", SBI_GUARD("CLEAN := $(if $(filter clean,$(MAKECMDGOALS)),1)\n",
                                "ifneq ($(CLEAN),1)", ""), NULL, false},
        {"unmodelled", SBI_GUARD("", "ifneq ($(sort $(wildcard build/x)),)", ""),
         NULL, false},
        {"else", SBI_GUARD("X := a\n", "ifeq ($(X),a)\nY := 1\nelse", ""), NULL,
         true},
        {"else_open", SBI_GUARD("", "ifeq ($(shell uname),a)\nY := 1\nelse", ""),
         NULL, false},
        {"union", SBI_GUARD(SBI_MISSING(SBI_IF_UNAME SBI_LIBA "else\n"
                                        "LIBS := vendor/lib/libb.a\nendif\n"),
                            SBI_MISSING_COND, ""), k_sbi_libs, true},
        {"union_missing", SBI_GUARD(SBI_MISSING(SBI_IF_UNAME SBI_LIBA "else\n"
                                                "LIBS := vendor/lib/libb.a\n"
                                                "endif\n"),
                                    SBI_MISSING_COND, ""), k_sbi_liba, false},
        {"one_branch", SBI_GUARD(SBI_MISSING(SBI_IF_UNAME SBI_LIBA "endif\n"),
                                 SBI_MISSING_COND, ""), k_sbi_liba, false},
        {"appended", SBI_GUARD(SBI_MISSING(SBI_LIBA "LIBS += vendor/lib/liba.a\n"),
                               SBI_MISSING_COND, ""), k_sbi_liba, false},
        {"eval", SBI_GUARD(SBI_MISSING(SBI_LIBA "$(eval LIBS := vendor/lib/z.a)\n"),
                           SBI_MISSING_COND, ""), k_sbi_liba, false},
        {"target_specific", SBI_GUARD(SBI_MISSING(SBI_LIBA "build/a.o: LIBS := z\n"),
                                      SBI_MISSING_COND, ""), k_sbi_liba, false},
        {"environment", SBI_GUARD("", "ifneq ($(FOO),)", ""), NULL, false},
        {"q20", SBI_GUARD("", "ifeq ($(wildcard d/*),)", ""), k_sbi_dot, false},
        {"q84", SBI_GUARD("", "ifeq ($(wildcard d/*/m),)", ""), k_sbi_dotdir, false},
        {"q51", SBI_GUARD("L := a%\n", "ifeq ($(filter a\\%,$(L)),)\nelse", ""),
         NULL, false},
        {"q80", SBI_GUARD("", "ifeq ($(wildcard d/s/),d/s/)", ""), k_sbi_ds, false},
        {"q82", SBI_GUARD("", "ifeq ($(wildcard d//x),d//x)", ""), k_sbi_dx, false},
        {"q83", SBI_GUARD("", "ifeq ($(wildcard d/*),d/a d/b)", ""), k_sbi_dab, false},
        {"filter_out_all", SBI_GUARD("", "ifeq ($(filter-out a,a),)", ""), NULL, false},
        {"glob_created", SBI_GUARD("X := $(shell mkdir -p d && touch d/flag)\n", "ifneq ($(wildcard d/flag),)", ""), NULL, false},
        {"glob_other", SBI_GUARD("X := $(shell mkdir -p e)\n", "ifneq ($(wildcard zz/flag),)", ""), NULL, true},
        {"t01", SBI_GUARD("X := $(shell cp -r tools/seed d/new)\n", "ifneq ($(wildcard d/*/.unverified),)", ""), NULL, false},
        {"t03", SBI_GUARD("X := $(shell mkdir -p d/n && cp tools/seed/* d/n/)\n", "ifneq ($(wildcard d/*/marker),)", ""), NULL, false},
        {"w02", SBI_GUARD("X := $(call shell,cp -r tools/seed d/new)\n", "ifneq ($(wildcard d/*/.unverified),)", ""), NULL, false},
    };
    TEST_CASE("semantic_build_inputs: a missing include a conditional "
             "provably skips narrows, and any input that may take the branch "
             "widens") {
        ASSERT(sbi_guard_cases(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* ---- the real Tor marker: host target, default Tor, archives globbed ------------ */

/* The Makefile's shape: ZCL_TARGET picks the cross triple in a branch,
 * the triple picks the Tor tree, and the marker is read only while an
 * archive of that tree is missing. `target` is the ZCL_TARGET line. */
#define SBI_TARGET(target)                                                     \
    target "ZCL_CROSS_TRIPLE :=\nifneq ($(ZCL_TARGET),host)\n"                 \
    "ifeq ($(ZCL_TARGET),windows-x86_64)\n"                                    \
    "ZCL_CROSS_TRIPLE := x86_64-w64-mingw32\nelse\n"                           \
    "$(error unknown ZCL_TARGET)\nendif\nendif\n"
#define SBI_TOR_TREE(target, more)                                             \
    SBI_TARGET(target) more                                                    \
    "ZCL_TOR_TREE := $(if $(ZCL_CROSS_TRIPLE),vendor/cross/"                   \
    "$(ZCL_CROSS_TRIPLE)/tor,vendor/tor)\n"                                    \
    "TOR_ARCHIVE_PATHS := $(ZCL_TOR_TREE)/libtor.a \\\n"                        \
    "\t$(ZCL_TOR_TREE)/src/ext/keccak-tiny/libkeccak-tiny.a\n"                 \
    "ZCL_TOR ?= full\nifeq ($(filter full stub,$(ZCL_TOR)),)\n"                \
    "$(error ZCL_TOR must be full or stub)\nendif\n"                           \
    "TOR_MISSING_ARCHIVES := $(filter-out $(wildcard $(TOR_ARCHIVE_PATHS)),"  \
    "$(TOR_ARCHIVE_PATHS))\nifeq ($(ZCL_TOR),full)\n"
#define SBI_TOR_REAL(target, more)                                             \
    SBI_GUARD(SBI_TOR_TREE(target, more),                                      \
              "ifneq ($(strip $(TOR_MISSING_ARCHIVES)),)", "endif\n")
#define SBI_HOST "ZCL_TARGET ?= host\n"
#define SBI_WIN "ZCL_TARGET ?= windows-x86_64\n"
/* ZCL_TOR read directly: its default (full) skips the branch. */
#define SBI_TOR_KNOB(lines) SBI_GUARD(lines, "ifneq ($(ZCL_TOR),full)", "")

static const char *const k_sbi_tor_host[] = {
    "vendor/tor/libtor.a", "!\n",
    "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a", "!\n", NULL};
static const char *const k_sbi_tor_host_one[] = {"vendor/tor/libtor.a", "!\n",
                                                 NULL};
static const char *const k_sbi_tor_cross[] = {
    "vendor/cross/x86_64-w64-mingw32/tor/libtor.a", "!\n",
    "vendor/cross/x86_64-w64-mingw32/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
    "!\n", NULL};

/* host-target-default-tor reads ZCL_TARGET and ZCL_TOR as their one
 * top-level ?= line gives them; any other line that can set them, and any
 * other ?= variable, is any text. A branch make provably does not take
 * (ZCL_TARGET is host) assigns nothing; one it may take still does. */
static int sbit_t_host_target_tor(void)
{
    int failures = 0;
    static const struct sbi_gcase cases[] = {
        {"tor_host", SBI_TOR_REAL(SBI_HOST, ""), k_sbi_tor_host, true},
        {"tor_host_one_missing", SBI_TOR_REAL(SBI_HOST, ""), k_sbi_tor_host_one,
         false},
        {"tor_host_none", SBI_TOR_REAL(SBI_HOST, ""), NULL, false},
        {"tor_host_cross_only", SBI_TOR_REAL(SBI_HOST, ""), k_sbi_tor_cross, false},
        {"tor_cross_default", SBI_TOR_REAL(SBI_WIN, ""), k_sbi_tor_host, false},
        /* The reading unions the empty triple a later := replaces: widen. */
        {"tor_cross_default_built", SBI_TOR_REAL(SBI_WIN, ""), k_sbi_tor_cross, false},
        {"tor_cross_set", SBI_TOR_REAL("ZCL_TARGET := windows-x86_64\n", ""),
         k_sbi_tor_host, false},
        {"tor_target_env", SBI_TOR_REAL("", ""), k_sbi_tor_host, false},
        {"tor_target_appended", SBI_TOR_REAL(SBI_HOST "ZCL_TARGET += x\n", ""),
         k_sbi_tor_host, false},
        {"tor_target_in_branch", SBI_TOR_REAL(SBI_IF_UNAME SBI_HOST "endif\n", ""),
         k_sbi_tor_host, false},
        {"tor_triple_undecided", SBI_TOR_REAL(SBI_HOST, SBI_IF_UNAME
                                              "ZCL_CROSS_TRIPLE := x86_64-w64-"
                                              "mingw32\nendif\n"),
         k_sbi_tor_host, false},
        {"tor_default", SBI_TOR_KNOB("ZCL_TOR ?= full\n"), NULL, true},
        {"tor_env", SBI_TOR_KNOB(""), NULL, false},
        {"tor_reassigned", SBI_TOR_KNOB("ZCL_TOR ?= full\n" SBI_IF_UNAME
                                        "ZCL_TOR := stub\nendif\n"), NULL, false},
        {"tor_appended", SBI_TOR_KNOB("ZCL_TOR ?= full\nZCL_TOR += stub\n"), NULL,
         false},
        {"tor_target_specific", SBI_TOR_KNOB("ZCL_TOR ?= full\n"
                                             "build/a.o: ZCL_TOR := stub\n"),
         NULL, false},
        {"tor_default_late", SBI_GUARD("", "ifneq ($(ZCL_TOR),full)",
                                       "ZCL_TOR ?= full\n"), NULL, false},
        {"other_default", SBI_GUARD("ZCL_FOO ?= full\n", "ifneq ($(ZCL_FOO),full)",
                                    ""), NULL, false},
    };
    TEST_CASE("semantic_build_inputs: the Tor marker is skipped only for the "
             "host target and default Tor with every archive present") {
        ASSERT(sbi_guard_cases(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* An assignment in a branch make provably does not take is no value of its
 * variable; one in a branch the reading cannot decide still is. */
#define SBI_LIBB "LIBS := vendor/lib/libb.a\n"
#define SBI_PRUNE(lines)                                                       \
    SBI_GUARD(SBI_MISSING("X := a\n" SBI_LIBA lines), SBI_MISSING_COND, "")
static int sbit_t_pruned_branch(void)
{
    int failures = 0;
    static const struct sbi_gcase cases[] = {
        {"prune_if", SBI_PRUNE("ifeq ($(X),b)\n" SBI_LIBB "endif\n"), k_sbi_liba,
         true},
        {"prune_else", SBI_PRUNE("ifeq ($(X),a)\n" SBI_LIBA "else\n" SBI_LIBB
                                 "endif\n"), k_sbi_liba, true},
        {"prune_else_if", SBI_PRUNE("ifeq ($(X),a)\n" SBI_LIBA "else ifeq ($(X),c)\n"
                                    SBI_LIBB "endif\n"), k_sbi_liba, true},
        {"prune_inner", SBI_PRUNE(SBI_IF_UNAME "ifneq ($(X),a)\n" SBI_LIBB
                                  "endif\nendif\n"), k_sbi_liba, true},
        {"prune_outer", SBI_PRUNE("ifeq ($(X),b)\n" SBI_IF_UNAME SBI_LIBB
                                  "endif\nendif\n"), k_sbi_liba, true},
        {"keep_taken", SBI_PRUNE("ifeq ($(X),a)\n" SBI_LIBB "endif\n"), k_sbi_liba,
         false},
        {"keep_undecided", SBI_PRUNE(SBI_IF_UNAME SBI_LIBB "endif\n"), k_sbi_liba,
         false},
        {"keep_undecided_else", SBI_PRUNE(SBI_IF_UNAME SBI_LIBA "else\n" SBI_LIBB
                                          "endif\n"), k_sbi_liba, false},
        {"keep_later_x", SBI_PRUNE("ifeq ($(X),b)\n" SBI_LIBB "endif\n"
                                   SBI_IF_UNAME "X := b\nendif\n"
                                   "ifeq ($(X),b)\n" SBI_LIBB "endif\n"),
         k_sbi_liba, false},
    };
    TEST_CASE("semantic_build_inputs: an assignment in a branch make provably "
             "does not take is pruned, any other is unioned") {
        ASSERT(sbi_guard_cases(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* A command make runs after it read the deciding directive cannot change
 * what that directive read: under the premises nothing restarts make (a
 * missing include it could make is UNKNOWN or skipped, an existing one is
 * current). One at or before the directive still refuses the skip, and so
 * does a lazy definition read before it or any line of another makefile,
 * whenever make runs it. */
#define SBI_FLAG_COND "ifneq ($(wildcard d/flag),)"
#define SBI_TOUCH "$(shell mkdir -p d && touch d/flag)"
#define SBI_TOR_AFTER(pre, post)                                               \
    SBI_GUARD(SBI_TOR_TREE(SBI_HOST, "") pre,                                  \
              "ifneq ($(strip $(TOR_MISSING_ARCHIVES)),)", "endif\n" post)
#define SBI_TOR_KEY "KEY := $(shell tools/key.sh '$(TOR_ARCHIVE_PATHS)')\n"
static const char *const k_sbi_other_mk[] = {"other.mk", "X := " SBI_TOUCH "\n",
                                             NULL};
static int sbit_t_after_directive(void)
{
    int failures = 0;
    static const struct sbi_gcase cases[] = {
        {"after_touch", SBI_GUARD("", SBI_FLAG_COND, "X := " SBI_TOUCH "\n"),
         NULL, true},
        {"after_touch_in_branch", SBI_GUARD("", "ifeq ($(wildcard d/flag),)\n"
                                            "X := " SBI_TOUCH "\nelse", ""),
         NULL, true},
        {"after_eval", SBI_GUARD("", SBI_FLAG_COND, "define T\n$(1):\n"
                                 "\tmkdir -p d && touch d/flag\nendef\n"
                                 "$(eval $(call T,d/flag))\n"), NULL, true},
        {"before_touch", SBI_GUARD(SBI_IF_UNAME "X := " SBI_TOUCH "\n",
                                   SBI_FLAG_COND, "endif\n"), NULL, false},
        {"before_lazy", SBI_GUARD("MK = " SBI_TOUCH "\n", SBI_FLAG_COND,
                                  "X := $(MK)\n"), NULL, false},
        {"other_file_after", SBI_GUARD("", SBI_FLAG_COND, "include other.mk\n"),
         k_sbi_other_mk, false},
        {"tor_key_after", SBI_TOR_AFTER("", SBI_TOR_KEY), k_sbi_tor_host, true},
        {"tor_key_before", SBI_TOR_AFTER(SBI_TOR_KEY, ""), k_sbi_tor_host, false},
    };
    TEST_CASE("semantic_build_inputs: a parse-time command after the "
             "deciding directive leaves the skip; one before it refuses it") {
        ASSERT(sbi_guard_cases(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* make remakes a makefile it read that a rule targets (cfg.mk here, by
 * the cmp/mv idiom on FORCE; a pattern rule; the root makefile itself)
 * and, when that changed it, reads every makefile again: the restarted
 * parse sees what the first one's later commands did, so a skip then
 * counts every command. Not for an include only the first parse reads,
 * under ifeq ($(strip $(MAKE_RESTARTS)),), while no line sets
 * MAKE_RESTARTS: make sets it on every restarted parse. */
#define SBI_CFG_RECIPE                                                         \
    "\t@printf '# cfg v2\\n' > $@.tmp; cmp -s $@.tmp $@ || mv $@.tmp $@; "      \
    "rm -f $@.tmp\nFORCE:\n"
#define SBI_CFG_RULE "-include cfg.mk\ncfg.mk: FORCE\n" SBI_CFG_RECIPE
#define SBI_FIRST_PARSE "ifeq ($(strip $(MAKE_RESTARTS)),)"
#define SBI_RM_TOR "X := $(shell rm -f vendor/tor/libtor.a)\n"
#define SBI_TOR_FIRST(post)                                                    \
    SBI_GUARD(SBI_TOR_TREE(SBI_HOST, ""),                                      \
              "ifneq ($(strip $(TOR_MISSING_ARCHIVES)),)\n" SBI_FIRST_PARSE,   \
              "endif\nendif\n" post)
static const char *const k_sbi_cfg[] = {"cfg.mk", "# cfg v1\n", NULL};
static const char *const k_sbi_tor_cfg[] = {
    "vendor/tor/libtor.a", "!\n",
    "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a", "!\n",
    "cfg.mk", "# cfg v1\n", NULL};
static int sbit_t_restart(void)
{
    int failures = 0;
    static const struct sbi_gcase cases[] = {
        {"restart_touch", SBI_GUARD("", SBI_FLAG_COND, "X := " SBI_TOUCH "\n"
                                    SBI_CFG_RULE), k_sbi_cfg, false},
        {"restart_tor", SBI_TOR_AFTER("", SBI_RM_TOR SBI_CFG_RULE),
         k_sbi_tor_cfg, false},
        {"restart_pattern", SBI_GUARD("", SBI_FLAG_COND, "X := " SBI_TOUCH "\n"
                                      "-include cfg.mk\n%.mk: FORCE\n"
                                      SBI_CFG_RECIPE), k_sbi_cfg, false},
        {"restart_root", SBI_GUARD("", SBI_FLAG_COND, "X := " SBI_TOUCH "\n"
                                   SBI_ROOT_NAME ": FORCE\n\t@test -f d/r || "
                                   "{ touch d/r && touch $@; }\nFORCE:\n"),
         NULL, false},
        {"restart_no_rule", SBI_GUARD("", SBI_FLAG_COND, "X := " SBI_TOUCH "\n"
                                      "-include cfg.mk\n"), k_sbi_cfg, true},
        {"restart_first_parse", SBI_GUARD("", SBI_FLAG_COND "\n" SBI_FIRST_PARSE,
                                          "endif\nX := " SBI_TOUCH "\n"
                                          SBI_CFG_RULE), k_sbi_cfg, true},
        {"restart_first_parse_outer", SBI_GUARD(SBI_FIRST_PARSE "\n",
                                                SBI_FLAG_COND, "endif\nX := "
                                                SBI_TOUCH "\n" SBI_CFG_RULE),
         k_sbi_cfg, true},
        {"restart_first_parse_set", SBI_GUARD("override MAKE_RESTARTS :=\n",
                                              SBI_FLAG_COND "\n" SBI_FIRST_PARSE,
                                              "endif\nX := " SBI_TOUCH "\n"
                                              SBI_CFG_RULE), k_sbi_cfg, false},
        {"restart_first_parse_else", SBI_GUARD("", SBI_FLAG_COND "\n"
                                               SBI_FIRST_PARSE "\nY := 1\nelse",
                                               "endif\nX := " SBI_TOUCH "\n"
                                               SBI_CFG_RULE), k_sbi_cfg, false},
        {"restart_tor_first_parse", SBI_TOR_FIRST(SBI_RM_TOR SBI_CFG_RULE),
         k_sbi_tor_cfg, true},
    };
    TEST_CASE("semantic_build_inputs: a makefile a rule may remake restarts "
             "make, and a skip then counts every command, unless only the "
             "first parse reads the include") {
        ASSERT(sbi_guard_cases(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* Before a restarted parse make runs the recipes that remade a makefile,
 * not only the first parse's commands: a recipe (its text, a variable a
 * later line sets, or a script) may create what the directive globs. A
 * built-in rule remakes a makefile too: cfg from a newer cfg.sh. Each
 * widens; only an include the first parse alone reads still narrows. */
#define SBI_CFG_TOUCH "-include cfg.mk\ncfg.mk: FORCE\n\t@mkdir -p d && touch d/flag\n"
static const char *const k_sbi_cfg_sh[] = {"cfg", "# cfg v1\n", "cfg.sh",
                                           "# cfg v2\n", NULL};
static const char *const k_sbi_cfg_script[] = {
    "cfg.mk", "# cfg v1\n", "tools/mk.sh", "mkdir -p d && touch d/flag\n",
    NULL};
static int sbit_t_restart_recipes(void)
{
    int failures = 0;
    static const struct sbi_gcase cases[] = {
        {"restart_recipe_touch", SBI_GUARD("", SBI_FLAG_COND, SBI_CFG_TOUCH
                                           SBI_CFG_RECIPE), k_sbi_cfg, false},
        {"restart_recipe_later_var",
         SBI_GUARD("", SBI_FLAG_COND, "-include cfg.mk\ncfg.mk: FORCE\n"
                   "\t@$(MK)\n" SBI_CFG_RECIPE "MK := mkdir -p d && touch "
                   "d/flag\n"), k_sbi_cfg, false},
        {"restart_recipe_script",
         SBI_GUARD("", SBI_FLAG_COND, "-include cfg.mk\ncfg.mk: FORCE\n"
                   "\t@sh tools/mk.sh\n" SBI_CFG_RECIPE), k_sbi_cfg_script,
         false},
        {"restart_builtin", SBI_GUARD("", SBI_FLAG_COND, "X := " SBI_TOUCH
                                      "\n-include cfg\n"), k_sbi_cfg_sh, false},
        {"restart_recipe_first_parse",
         SBI_GUARD("", SBI_FLAG_COND "\n" SBI_FIRST_PARSE,
                   "endif\n" SBI_CFG_TOUCH SBI_CFG_RECIPE), k_sbi_cfg, true},
        {"restart_builtin_first_parse",
         SBI_GUARD("", SBI_FLAG_COND "\n" SBI_FIRST_PARSE, "endif\nX := "
                   SBI_TOUCH "\n-include cfg\n"), k_sbi_cfg_sh, true},
    };
    TEST_CASE("semantic_build_inputs: a restart runs the remaking recipes "
             "first, and a built-in rule may remake a makefile, so a skip "
             "stands then only for an include the first parse alone reads") {
        ASSERT(sbi_guard_cases(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* make drops a leading ./ from a file name (not a doubled slash): an
 * include and the rule that makes it name one file however each spells
 * it. */
#define SBI_DOT_INC(inc, target)                                               \
    "all: build/a.o\n" SBI_OBJ_RULE "-include " inc "\n" target                \
    ":\n\tcp tools/tpl.mk $@\n" SBI_GEN_RULE
static int sbit_t_dot_slash(void)
{
    int failures = 0;
    static const struct sbi_gcase cases[] = {
        {"i01", SBI_DOT_INC("./build/gen.mk", "build/gen.mk"), NULL, false},
        {"i02", SBI_DOT_INC("build/gen.mk", "./build/gen.mk"), NULL, false},
        {"i01_twice", SBI_DOT_INC(".//./build/gen.mk", "build/gen.mk"), NULL, false},
        {"i04", SBI_DOT_INC("build//gen.mk", "build/gen.mk"), NULL, true},
    };
    TEST_CASE("semantic_build_inputs: an include a rule makes under ./ "
             "widens") {
        ASSERT(sbi_guard_cases(cases, SBI_COUNT(cases)));
    } TEST_END
    return failures;
}

/* A rule whose targets a function computes makes a missing include its
 * text names, directly or through a variable: widen. One whose text names
 * none (j_subst: $(subst) spells the name only once make runs it) narrows
 * under computed-targets-not-includes, recorded with the first such rule. */
static int sbit_t_computed_targets(void)
{
    int failures = 0;
    static const char *const changed[] = {"tools/x.sh"};
    static const struct sbi_case cases[] = {
        {"j15", SBI_DOT_INC("./build/gen.mk", "$(addprefix ./,build/gen.mk)"), NULL, NULL},
        {"j18", SBI_DOT_INC("build/gen.mk", "N := build/gen.mk\n$(addprefix ./,$(N))"),
         NULL, NULL},
        {"j19", SBI_DOT_INC("build/gen.mk", "$(foreach w,build/gen.mk,$(w))"), NULL, NULL},
        {"j23", SBI_DOT_INC("build/gen.mk", "$(subst x,y,build/gen.mk)"), NULL, NULL},
        {"j26", SBI_DOT_INC("build/gen.mk", "ID = $(1)\n$(call ID,build/gen.mk)"), NULL, NULL},
        {"j29", SBI_DOT_INC("build/gen.mk", "N = build/gen.mk\n$(value N)"), NULL, NULL},
        {"j30", SBI_DOT_INC("build/gen.mk", "$(join build/,gen.mk)"), NULL, NULL},
        {"j33", SBI_DOT_INC("build/gen.mk", "$(patsubst %,./%,build/gen.mk)"), NULL, NULL},
    };
    struct sbi_run r = {0};
    const struct zcl_devloop_facts_plan_premise *p = &r.rep.make_premise;
    TEST_CASE("semantic_build_inputs: a computed rule target that names a "
             "missing include widens; one that names none is recorded") {
        ASSERT(sbi_cases_widen(cases, SBI_COUNT(cases)));
        ASSERT(sbi_consume("sbi_ct_subst", SBI_DOT_INC("build/gen.mk",
                           "$(subst Q,.,build/genQmk)"), changed, 1, &r) &&
               sbi_narrowed(&r));
        ASSERT(p->premises == ZCL_DEVLOOP_PREMISE_COMPUTED_TARGETS_NOT_INCLUDES &&
               strcmp(p->include, "build/gen.mk") == 0 && p->nincludes == 1);
        ASSERT(strcmp(p->target, "$(subst Q,.,build/genQmk)") == 0 &&
               strcmp(p->target_at, SBI_ROOT_NAME ":5") == 0 && p->ntargets == 1);
    } TEST_END
    zcl_devloop_facts_report_free(&r.rep);
    return failures;
}

/* A line that is no definition, directive or rule its text spells, and
 * that holds a reference, may expand to a rule: a variable holding "x:" or
 * ":", a top-level $(call), $(foreach) or $(if). A static rule's target
 * pattern, or a % pattern a computed target list is built from, may match
 * a missing include too. Each widens while it names the include; the rest
 * are recorded under computed-targets-not-includes. */
#define SBI_BARE(lines)                                                        \
    "all: build/a.o\n" SBI_OBJ_RULE "-include build/gen.mk\n" lines "\n"       \
    SBI_GEN_RULE
#define SBI_TPL ": tools/tpl.mk ; cp tools/tpl.mk "
#define SBI_TPL_RECIPE "\n\tcp tools/tpl.mk $@"
#define SBI_OBJS_IN "OBJS := $(patsubst tools/%.in,build/%.mk,$(wildcard tools/*.in))\n"
static int sbit_t_computed_lines(void)
{
    int failures = 0;
    static const char *const changed[] = {"tools/x.sh"};
    static const struct sbi_case cases[] = {
        {"t28", SBI_BARE("R := build/gen.mk:\n$(R)" SBI_TPL_RECIPE), NULL, NULL},
        {"t30", SBI_BARE("C := :\nbuild/gen.mk$(C)" SBI_TPL_RECIPE), NULL, NULL},
        {"t36", SBI_BARE("RULE = $(1)" SBI_TPL "$(1)\n$(call RULE,build/gen.mk)"),
         NULL, NULL},
        {"t37", SBI_BARE("$(foreach f,build/gen.mk,$(f)" SBI_TPL "$(f))"), NULL, NULL},
        {"t38", SBI_BARE("$(if 1,build/gen.mk" SBI_TPL "build/gen.mk)"), NULL, NULL},
        {"t10", SBI_BARE(SBI_OBJS_IN "$(OBJS): build/%.mk: tools/%.in\n\tcp $< $@"),
         "tools/gen.in", "x\n"},
        {"t11", SBI_BARE("$(subst Q,.,build/genQmk): build/%.mk: tools/%.in\n\tcp $< $@"),
         "tools/gen.in", "x\n"},
        {"t12", SBI_BARE("$(subst Q,%,build/Q.mk): tools/tpl.mk" SBI_TPL_RECIPE),
         NULL, NULL},
        {"t33", SBI_BARE(SBI_OBJS_IN "$(OBJS): tools/tpl.mk" SBI_TPL_RECIPE),
         "tools/gen.in", "x\n"},
    };
    struct sbi_run r = {0};
    const struct zcl_devloop_facts_plan_premise *p = &r.rep.make_premise;
    TEST_CASE("semantic_build_inputs: a line that may expand to a rule "
             "making a missing include widens; one naming none is recorded") {
        ASSERT(sbi_cases_widen(cases, SBI_COUNT(cases)));
        ASSERT(sbi_consume("sbi_ct_bare", SBI_BARE("R := $(subst Q,.,build/genQmk):\n"
                           "$(R)" SBI_TPL_RECIPE), changed, 1, &r) &&
               sbi_narrowed(&r));
        ASSERT(p->premises == ZCL_DEVLOOP_PREMISE_COMPUTED_TARGETS_NOT_INCLUDES &&
               strcmp(p->include, "build/gen.mk") == 0);
        ASSERT(strcmp(p->target, "$(R)") == 0 &&
               strcmp(p->target_at, SBI_ROOT_NAME ":6") == 0 && p->ntargets == 2);
    } TEST_END
    zcl_devloop_facts_report_free(&r.rep);
    return failures;
}

/* The premises every skip rests on, and the plan's. */
#define SBI_EVERY_SKIP (ZCL_DEVLOOP_PREMISE_BUILD_READS_PLANNED_TREE | \
                        ZCL_DEVLOOP_PREMISE_NO_COMMAND_LINE_OVERRIDE)
#define SBI_PLAN_PREMISE ZCL_DEVLOOP_PREMISE_PARSE_COMMANDS_NO_INCLUDE_WRITES

/* A skipped include is recorded with the directive, its premises and the
 * paths it globbed, so a reviewer can falsify the narrow. A skip that
 * rests on a glob records the plan premise too. */
static int sbit_t_guard_record(void)
{
    int failures = 0;
    static const char *const changed[] = {"tools/x.sh"};
    struct sbi_run e = {0}, v = {0};
    const struct zcl_devloop_facts_guard *g;
    TEST_CASE("semantic_build_inputs: a skipped include records its reading") {
        ASSERT(sbi_consume_files("sbi_guard_rec_e", SBI_EPOCH, NULL, changed, 1, &e));
        ASSERT(e.rep.nguards == 1);
        g = &e.rep.guards[0];
        ASSERT(strcmp(g->include, "build/ready.mk") == 0);
        ASSERT(strcmp(g->guard, "ifneq ($(strip $(LEASES)),)") == 0);
        ASSERT(g->premises == (ZCL_DEVLOOP_PREMISE_EPOCH_ONE_COMPONENT | SBI_EVERY_SKIP));
        /* PROFILES holds build-only: the zero epoch's else branch is not
         * taken, so its path is neither a value of EPOCH nor globbed. */
        ASSERT(g->nglobs == 1 && g->found[0][0] == '\0');
        ASSERT(strcmp(g->glob[0], "build/obj/epochs/{epoch}/.unverified") == 0);
        ASSERT(e.rep.make_premise.premises == SBI_PLAN_PREMISE && e.rep.make_premise.nskips == 1 &&
               strcmp(e.rep.make_premise.include, "build/ready.mk") == 0);
        ASSERT(sbi_consume_files("sbi_guard_rec_v", SBI_GUARD(SBI_VENDOR, "ifneq ($(strip "
                                 "$(MISSING) $(REPAIR)),)", ""), k_sbi_liba, changed, 1, &v));
        ASSERT(v.rep.nguards == 1);
        g = &v.rep.guards[0];
        ASSERT(g->premises == (ZCL_DEVLOOP_PREMISE_NO_REPAIR_GOAL | SBI_EVERY_SKIP));
        ASSERT(g->nglobs == 1 && strcmp(g->glob[0], "vendor/lib/liba.a") == 0 &&
               strcmp(g->found[0], "vendor/lib/liba.a") == 0);
    } TEST_END
    zcl_devloop_facts_report_free(&e.rep);
    zcl_devloop_facts_report_free(&v.rep);
    return failures;
}

/* A plan that reads an optional include, missing (p02: a parse-time
 * script) or existing, records the premise parse-commands-no-include-writes
 * when a parse-time command is not provably read-only. */
static int sbit_t_plan_record(void)
{
    int failures = 0;
    static const char *const changed[] = {"tools/x.sh"};
    struct sbi_run s = {0}, u = {0}, x = {0};
    const struct zcl_devloop_facts_plan_premise *p = &s.rep.make_premise;
    const struct zcl_devloop_facts_plan_premise *q = &x.rep.make_premise;
    TEST_CASE("semantic_build_inputs: a parse-time script records the plan premise") {
        ASSERT(sbi_consume("sbi_pp_s", "X := $(shell tools/mkgen.sh)\n" SBI_P_TAIL,
                           changed, 1, &s) && sbi_narrowed(&s));
        ASSERT(p->premises == SBI_PLAN_PREMISE && p->nincludes == 1 && p->nskips == 0 &&
               strcmp(p->include, "build/gen.mk") == 0);
        ASSERT(strcmp(p->command, "tools/mkgen.sh") == 0 && p->ncommands == 1 &&
               strcmp(p->command_at, SBI_ROOT_NAME ":1") == 0);
        ASSERT(sbi_consume("sbi_pp_u", "X := $(shell uname -m)\n" SBI_P_TAIL, changed,
                           1, &u) && u.rep.make_premise.premises == 0);
        ASSERT(sbi_consume_with("sbi_pp_x", "X := $(shell tools/mkgen.sh)\n" SBI_P_TAIL,
                                "build/gen.mk", "# old\n", changed, 1, &x) &&
               sbi_narrowed(&x));
        ASSERT(q->premises == SBI_PLAN_PREMISE && q->nincludes == 0 && q->nexisting == 1 &&
               strcmp(q->include, "build/gen.mk") == 0 &&
               strcmp(q->command, "tools/mkgen.sh") == 0);
    } TEST_END
    zcl_devloop_facts_report_free(&s.rep);
    zcl_devloop_facts_report_free(&u.rep);
    zcl_devloop_facts_report_free(&x.rep);
    return failures;
}

/* A parse-time command narrows but is recorded as unproven when a call
 * form runs it ($(call shell,...)), when SHELL, .SHELLFLAGS or PATH is
 * assigned or a variable is exported (any command may then run anything:
 * echo is no longer a reader; make passes exported variables such as
 * LD_PRELOAD to $(shell)), or when an $(eval) runs text a reference or $$(
 * computes. An $(eval) line may expand to a rule too: it records
 * computed-targets-not-includes as well. */
#define SBI_EVAL_PREMISE ZCL_DEVLOOP_PREMISE_COMPUTED_TARGETS_NOT_INCLUDES
struct sbi_pcase {
    const char *id, *makefile, *command;
    unsigned premises;
};

static int sbit_t_premise_forms(void)
{
    int failures = 0;
    static const char *const changed[] = {"tools/x.sh"};
    bool all = true;
    static const struct sbi_pcase cases[] = {
        {"u01", "X := $(call shell,tools/mkgen.sh)\n", "tools/mkgen.sh", 0},
        {"u05", "SHELL := tools/wrap.sh\nX := $(shell echo hi)\n", "echo hi", 0},
        {"v14", ".SHELLFLAGS := -c tools/mkgen.sh;eval\nX := $(shell echo hi)\n",
         "echo hi", 0},
        {"shell_target", "build/a.o: SHELL := tools/wrap.sh\nX := $(shell echo hi)\n",
         "echo hi", 0},
        {"path_export", "export PATH := tools/bin:$(PATH)\nX := $(shell cat tools/t)\n",
         "cat tools/t", 0},
        {"v12", "FR != cat tools/frag\n$(eval $(FR))\n", "$(FR)", SBI_EVAL_PREMISE},
        {"u06", "S := shell\n$(eval X := $$($(S) tools/mkgen.sh))\n",
         "X := $$($(S) tools/mkgen.sh)", SBI_EVAL_PREMISE},
        {"export", "export LD_PRELOAD := tools/x.so\nX := $(shell echo hi)\n", "echo hi", 0},
    };
    TEST_CASE("semantic_build_inputs: a call form, a reassigned shell or a "
             "computed $(eval) records the plan premise") {
        for (size_t k = 0; k < SBI_COUNT(cases); k++) {
            struct sbi_run r = {0};
            char tag[64], mk[1024];
            const struct zcl_devloop_facts_plan_premise *p = &r.rep.make_premise;
            bool ok;
            (void)snprintf(tag, sizeof(tag), "sbi_pf_%s", cases[k].id);
            (void)snprintf(mk, sizeof(mk), "%s%s", cases[k].makefile, SBI_P_TAIL);
            ok = sbi_consume(tag, mk, changed, 1, &r) && sbi_narrowed(&r) &&
                 p->premises == (SBI_PLAN_PREMISE | cases[k].premises) &&
                 p->nincludes == 1 &&
                 strcmp(p->include, "build/gen.mk") == 0 &&
                 strcmp(p->command, cases[k].command) == 0;
            if (!ok)
                printf("[premise %s not recorded: %u %s] ", cases[k].id,
                       p->premises, p->command);
            zcl_devloop_facts_report_free(&r.rep);
            all = all && ok;
        }
        ASSERT(all);
    } TEST_END
    return failures;
}

/* A skip that read ZCL_TARGET or ZCL_TOR's default records the premise
 * host-target-default-tor with the directive and the archives it globbed;
 * one that read neither does not. */
static int sbit_t_tor_record(void)
{
    int failures = 0;
    static const char *const changed[] = {"tools/x.sh"};
    struct sbi_run t = {0}, k = {0}, p = {0};
    const struct zcl_devloop_facts_guard *g;
    TEST_CASE("semantic_build_inputs: a Tor marker skip records "
             "host-target-default-tor") {
        ASSERT(sbi_consume_files("sbi_tor_rec_t", SBI_TOR_REAL(SBI_HOST, ""),
                                 k_sbi_tor_host, changed, 1, &t) &&
               sbi_narrowed(&t) && t.rep.nguards == 1);
        g = &t.rep.guards[0];
        ASSERT(strcmp(g->include, "build/ready.mk") == 0 &&
               strcmp(g->guard, "ifneq ($(strip $(TOR_MISSING_ARCHIVES)),)") == 0);
        ASSERT(g->premises == (ZCL_DEVLOOP_PREMISE_HOST_TARGET_DEFAULT_TOR |
                               SBI_EVERY_SKIP));
        ASSERT(g->nglobs == 2 && strcmp(g->glob[0], "vendor/tor/libtor.a") == 0 &&
               strcmp(g->found[0], "vendor/tor/libtor.a") == 0 &&
               strcmp(g->glob[1], "vendor/tor/src/ext/keccak-tiny/"
                                  "libkeccak-tiny.a") == 0);
        ASSERT(sbi_consume_files("sbi_tor_rec_k", SBI_TOR_KNOB("ZCL_TOR ?= full\n"),
                                 NULL, changed, 1, &k) && k.rep.nguards == 1 &&
               k.rep.guards[0].premises ==
                   (ZCL_DEVLOOP_PREMISE_HOST_TARGET_DEFAULT_TOR | SBI_EVERY_SKIP) &&
               k.rep.guards[0].nglobs == 0);
        ASSERT(sbi_consume_files("sbi_tor_rec_p", SBI_PRUNE("ifeq ($(X),b)\n"
                                 SBI_LIBB "endif\n"), k_sbi_liba, changed, 1, &p) &&
               p.rep.nguards == 1 && p.rep.guards[0].premises == SBI_EVERY_SKIP);
    } TEST_END
    zcl_devloop_facts_report_free(&t.rep);
    zcl_devloop_facts_report_free(&k.rep);
    zcl_devloop_facts_report_free(&p.rep);
    return failures;
}

int sbi_guard_suite(void)
{
    return sbit_t_parse_time_writers() | sbit_t_parse_time_quiet() |
           sbit_t_guarded_include() | sbit_t_guard_record() | sbit_t_plan_record() |
           sbit_t_dot_slash() | sbit_t_computed_targets() | sbit_t_computed_lines() |
           sbit_t_premise_forms() | sbit_t_host_target_tor() | sbit_t_pruned_branch() |
           sbit_t_tor_record() | sbit_t_after_directive() | sbit_t_restart() |
           sbit_t_restart_recipes();
}
