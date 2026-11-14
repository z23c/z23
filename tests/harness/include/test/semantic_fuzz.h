/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The semantic-facts differential fuzzer: its project generator, fixed reproducers, relocatable-ELF symbol reader and the per-case oracle the semantic_facts_fuzz group runs. */
#ifndef ZCL_TEST_SEMANTIC_FUZZ_H
#define ZCL_TEST_SEMANTIC_FUZZ_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── the generator (semantic_fuzz_gen.c, semantic_fuzz_templ.c) ─────────── */

/* Profile bits: drop a mutation family so the others are not drowned out.
 * __COUNTER__ and __LINE__ users make most plans fall back
 * ("position-dependent"), so the no-ctr-line profile narrows far more. */
enum {
    SFZ_NO_CTR = 1u,  /* no __COUNTER__ anywhere, no counter_c mutation */
    SFZ_NO_LINE = 2u, /* no __LINE__ anywhere */
    SFZ_NO_FLAG = 4u, /* no flag mutation */
};

struct sfz_meta {
    char kind[32];    /* the mutation kind */
    char detail[256]; /* what it changed */
    int ntus;         /* src/t0.c .. src/t<ntus-1>.c */
};

/* Write <dir>/before/ and <dir>/after/: a random multi-TU C23 project
 * (src/, inc1/, inc2/ and a Makefile whose CFLAGS_EXTRA line carries the
 * project's extra flags) and the same project after one mutation, plus
 * <dir>/meta.txt. `kind` NULL draws one; a kind name forces it. The same
 * seed and profile always write the same bytes. */
bool sfz_generate(uint64_t seed, unsigned profile, const char *kind,
                  const char *dir, struct sfz_meta *meta);

/* True when `kind` names a mutation kind sfz_generate() can force. */
bool sfz_kind_known(const char *kind);

/* mkdir -p with mode 0700. */
bool sfz_mkdirs(const char *path);
/* Write `n` bytes to <dir>/<rel>, creating its directories. */
bool sfz_put(const char *dir, const char *rel, const char *text, size_t n);
/* Make <dir>/<rel> a symbolic link to `target` (relative to the link's
 * own directory), replacing whatever is there and creating its
 * directories. A case lays a link out as a link and compares it by its
 * target text, as git does: retargeting it changes the link's path, and
 * editing the file it names changes only that file's path. */
bool sfz_symlink(const char *dir, const char *rel, const char *target);

/* ── the fixed reproducers (semantic_fuzz_repro.c) ──────────────────────── */

/* One file of a reproducer; NULL text: absent on that side. A text made
 * with SFZ_LINK("../hdr/a.h") is no content: that side has a symbolic
 * link at `path` to the target. */
struct sfz_file {
    const char *path;
    const char *before, *after;
};

#define SFZ_LINK_MARK "\001" "symlink:"
#define SFZ_LINK(target) SFZ_LINK_MARK target

struct sfz_repro {
    const char *name;   /* F<n>_... a false negative found (fixed, or
                           known-RED), pass_... or D<n>_... (a data
                           edit) a shape that must keep passing */
    const char *kind, *detail;
    bool gcc_deps;      /* the depfiles come from gcc, as the dev compile's */
    const char *known_red; /* non-NULL: expected to fail until this lands */
    const struct sfz_file *files;
    size_t nfiles;
    /* With known_red: the exact false-negative lines the case must report,
     * each ending in '\n', in report order. The case holds only when it
     * FAILs with exactly these lines; a PASS means the mark is stale. */
    const char *known_red_why;
    /* over_pinned: over_want is the exact count of TUs the plan selected
     * (predicted affected) whose cold object bytes did not change
     * (over-selection, a false-WIDE plan). The case holds only when its
     * measured over-selection equals over_want exactly, independent of
     * known_red: a rise is a precision regression and a fall means
     * over_want is stale and must come down. false (the default, every
     * reproducer this field predates): unchecked. */
    bool over_pinned;
    size_t over_want;
};

extern const struct sfz_repro k_sfz_repros[];
extern const size_t k_sfz_nrepros;

/* A reproducer that also sets the toolchain: the object compiler of each
 * side (NULL or "clang": the sensor's clang; "gcc", or any other name, is
 * looked up on PATH, and a case whose compiler is absent is a visible
 * SKIP) and the optimizer flags that replace -O1 in the argv (NULL: -O1;
 * several flags comma-separated; COMPILE/SENSOR when the sensor is handed
 * other flags than the compile; BEFORE>AFTER when they drift between the
 * sides). The sensor is told each side's compiler with --cc and a fixed
 * stand-in toolchain identity, as the facts rule tells it. */
struct sfz_tool_repro {
    struct sfz_repro r;
    const char *cc_before, *cc_after;
    const char *opt;
};

extern const struct sfz_tool_repro k_sfz_tool_repros[];
extern const size_t k_sfz_ntool_repros;

/* Write <dir>/before/ and <dir>/after/ of reproducer r. */
bool sfz_write_repro(const struct sfz_repro *r, const char *dir);

/* ── relocatable ELF64 symbols (semantic_fuzz_elf.c) ────────────────────── */

#define SFZ_NAME_MAX 128

/* One defined STT_FUNC or STT_OBJECT symbol of an ET_REL object: its
 * bytes (a NOBITS object: its size) and the RELA entries that patch them,
 * digested twice. `raw` takes each relocation's offset, type, target
 * symbol name and addend. `resolved` takes its offset and type and what it
 * addresses: for a section or local symbol defined in the object, the
 * content at the addressed offset (a merged string or constant, the object
 * it lands in with the position inside it, the function it lands in by
 * name, else the bytes up to the next symbol or the section end); for any
 * other symbol, its name and the addend. Equal `resolved` digests with
 * different `raw` ones differ only where the same content sits. */
struct sfz_sym {
    char name[SFZ_NAME_MAX];
    bool object;         /* STT_OBJECT, else STT_FUNC */
    bool local;          /* STB_LOCAL: a static, or a compiler-made clone */
    uint32_t shndx;
    uint64_t value, size;
    uint8_t raw[32];
    uint8_t resolved[32];
};

struct sfz_syms {
    struct sfz_sym *v;
    size_t n;
};

/* Read every defined function and every data object the source names of
 * the x86-64 little-endian ET_REL image `img` (a compiler-private .L label,
 * such as a string literal, is judged only through the relocations that
 * address it). Fails closed, naming the defect in
 * err, on any other shape, any out-of-range offset, symbol or string, or
 * an unterminated name. */
bool sfz_elf_syms(const uint8_t *img, size_t n, struct sfz_syms *out,
                  char *err, size_t errlen);
void sfz_syms_free(struct sfz_syms *f);
/* The k-th (0-based) symbol named `name`, or NULL. */
const struct sfz_sym *sfz_sym_find(const struct sfz_syms *f, const char *name,
                                   size_t k);

/* The DT_RUNPATH (else DT_RPATH) string of an ELF64 executable or shared
 * object, from its section headers. False when there is none or the file
 * is not ELF64 little-endian. */
bool sfz_elf_runpath(const char *path, char *out, size_t outlen);
/* Exact DT_NEEDED before DT_NULL, with no DT_RPATH/RUNPATH tag. */
bool sfz_elf_needs_without_runpath(const char *path, const char *soname);

/* ── one differential case (semantic_fuzz_case.c) ───────────────────────── */

struct sfz_env {
    char sensor[PATH_MAX]; /* absolute build/bin/z23-clang-manifest */
    char clang[PATH_MAX];  /* the clang of the LLVM the sensor links */
    char gcc[PATH_MAX];    /* gcc for gcc_deps cases, "" when absent */
    int jobs;              /* compiles and sensor runs at once */
    bool cold_sensor;      /* test-private standalone baseline */
    int outcome_fd;        /* case child pipe; must not leak to descendants */
};

struct sfz_case {
    char label[96];        /* "seed=<n> profile=<p>" or the reproducer name */
    char dir[PATH_MAX];    /* holds before/ and after/ */
    char kind[32], detail[256];
    bool gcc_deps;
    /* The object compiler of the before [0] and after [1] side, absolute;
     * "" is env->clang. */
    char cc[2][PATH_MAX];
    /* Comma-separated flags in place of -O1 in the compile's and the
     * sensor's argv alike, or COMPILE/SENSOR when the sensor is handed
     * other flags than the compile it describes, each side's own as
     * BEFORE>AFTER when they drift; "" (or an empty half) is -O1. */
    char opt[128];
};

enum sfz_status { SFZ_PASS, SFZ_FAIL, SFZ_NOOP, SFZ_ERROR };

struct sfz_outcome {
    enum sfz_status status;
    bool narrowed;         /* the plan's verdict narrowed */
    char vreason[64];      /* its fallback reason, "" when narrowed */
    size_t tus, predicted, changed, missed, over;
    size_t cfun;           /* functions with new bytes in changed objects */
    size_t cobj;           /* data objects with new bytes in changed objects */
    size_t covered_seed, covered_other, reloc, notcov;
    size_t seeds;          /* seeds the verdict names */
    double plan_s;
    char why[2048];        /* the first false-negative lines, or the error */
};

/* Compile every TU before and after (each side's compiler, -std=c23 and
 * the case's optimizer flags, -O1 by default, with the project's flags),
 * sense each, plan the change set in process with the
 * facts, and judge: (1) every TU the plan leaves unaffected has a
 * byte-identical object; (2) every function and data object with new bytes
 * or new addressed content (an addend alone that resolves to the same
 * content does not count) is a seed or is covered by a fallback or a
 * broadened TU after a header change, and so is every alias of a seed.
 * A PASS removes the case directory. */
bool sfz_run_case(const struct sfz_env *env, const struct sfz_case *c,
                  struct sfz_outcome *out);

#endif /* ZCL_TEST_SEMANTIC_FUZZ_H */
