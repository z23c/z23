/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fingerprint — behavioral fingerprinting of in-tree C functions.
 *
 * ── What it is ──────────────────────────────────────────────────────────
 * A DERIVED index of what a function DOES, computed by actually CALLING it
 * on a deterministic, signature-derived input corpus and hashing the
 * observable results:
 *
 *     fingerprint(f) = H( shape(f), { (input_k, observable_output_k) } )
 *
 * Nothing a human types is load-bearing. There is no annotation, no
 * allowlist, no `@pure` tag, and no per-function harness. The candidate set,
 * the input corpus, the call harness and the fingerprint are all recomputed
 * from source on every run, so the index cannot rot the way a hand-tagged
 * one does.
 *
 * It is NAME-BLIND, COMMENT-BLIND and SPELLING-BLIND on purpose. Two
 * functions with the same fingerprint are candidates for being the same
 * behavior under two names — the Type-4 clone that no textual or token-based
 * clone detector sees, and the one that mass code generation produces.
 *
 * ── The pipeline ────────────────────────────────────────────────────────
 *   1. SCAN     every tracked .c/.h: definitions, bodies, prototypes,
 *               macros, file-scope objects, enum constants.
 *   2. SELECT   a candidate must be (a) provably pure by a fail-closed
 *               transitive analysis of its own body and its whole callee
 *               closure, (b) REACHABLE — either externally linkable through
 *               a header prototype, or file-local in a unit whose whole
 *               source the probe can include — and (c) callable from a
 *               generated harness given only its signature.
 *   3. EMIT     one generated C probe per candidate, grouped into per-module
 *               translation units, plus a driver.
 *   4. COMPILE  the probe TUs; a probe that does not compile is EXCLUDED,
 *               never guessed at.
 *   5. RUN      each probe in a FORKED CHILD under an alarm, so a crash, a
 *               hang, or memory corruption from one probe cannot reach any
 *               other probe's result.
 *   6. STABILISE keep only fingerprints that are byte-identical across every
 *               configuration (see below). Anything that varies is reported
 *               as FALSE PURITY and is never fingerprinted.
 *   7. REPORT   group by (shape, fingerprint); re-test every matched group
 *               on a second, disjoint, adversarial corpus before calling it
 *               a candidate duplicate.
 *
 * ── LIMITS — read this before trusting any output ───────────────────────
 * This tool is a CANDIDATE GENERATOR. It never proves two functions are the
 * same function, and the following are things it will NEVER catch. Stated
 * plainly so the next reader does not over-trust it:
 *
 *  - A MATCH IS NOT A PROOF OF EQUIVALENCE. Agreement on a finite corpus is
 *    agreement on a finite corpus. Two functions that differ only on a rare
 *    branch (one input in 2^64, a specific magic constant, a length the
 *    corpus never generates) fingerprint identically. Every match is
 *    reported with the input count behind it precisely because that number,
 *    not the match, is the evidence.
 *  - IT ONLY SEES PURE, SYNTHESISABLE FUNCTIONS. Anything that touches I/O,
 *    the clock, the allocator, a lock, a socket, a database, a global, or a
 *    function static is excluded by construction. In a systems codebase that
 *    is most of the tree. The coverage number is small and is meant to be.
 *  - A FILE-LOCAL FUNCTION IS REACHED BY INCLUDING ITS DEFINING UNIT, NOT
 *    ITS HEADER. A `static` function has no external linkage, so a probe
 *    that included only a header could never call it. Its probe translation
 *    unit therefore `#include`s the whole defining `.c`, which makes the
 *    static callable and simultaneously drags in that unit's file-scope
 *    state, its other statics and its own include set. Two consequences are
 *    load-bearing and neither is papered over: a defining unit that will not
 *    compile that way, or whose symbols collide at link, costs every
 *    candidate in it, and that is COUNTED and named rather than dropped; and
 *    the purity analysis is NOT relaxed to pay for the reach — a static that
 *    touches file-scope state is refused exactly as an extern one is.
 *  - INDIRECT CALLS ARE A BLIND SPOT, AND THAT IS WHY THEY ARE REFUSED.
 *    A call through a function pointer cannot be resolved from source, so
 *    the purity analysis refuses the function rather than assuming. It
 *    therefore reports "cannot tell" far more often than "impure".
 *  - THE PURITY ANALYSIS IS SYNTACTIC. It reads source text, not a compiled
 *    IR. A body assembled by macro tricks, `#include`d mid-function, or
 *    hidden behind a preprocessor conditional this scanner did not evaluate
 *    can in principle slip past it. That is exactly why nothing is trusted
 *    on the static verdict alone: the EMPIRICAL stability filter (step 6) is
 *    the real gate, and the rate at which it catches the static analysis
 *    being wrong is reported on every run as the false-purity rate.
 *  - NON-DETERMINISM THAT IS STABLE ACROSS THE MEASURED CONFIGURATIONS IS
 *    NOT CAUGHT. The filter varies memory fill, process, address-space
 *    layout and optimisation level. A function whose output depends on
 *    something that is constant across all of those (the host CPU's feature
 *    set, the locale, the word size) will fingerprint stably HERE and
 *    differ on another machine. Fingerprints are host-local evidence.
 *  - THE CORPUS DECIDES WHAT CAN BE TOLD APART, AND IT IS THE WEAKEST PART.
 *    A validator only reveals itself on input it ACCEPTS. Uniform random
 *    bytes are rejected by every `is_hex`, `is_alphanumeric`, `label_valid`
 *    and `parse_request` in the tree, so on a naive corpus all of them
 *    return the same constant and all of them "match". The generator
 *    therefore cycles text alphabets and, for a parameter that has an
 *    identically-typed sibling, passes the sibling verbatim and one-bit-off
 *    so comparators see the equal case at all. That is a mitigation, not a
 *    solution: a function whose accepting set the corpus never reaches
 *    produces one constant output, and a fingerprint over one constant
 *    identifies nothing. Such functions are REFUSED (FP_MIN_DISTINCT) rather
 *    than reported, which is why the fingerprintable count is much smaller
 *    than the count of functions that merely ran.
 *  - THE SCANNER DOES NOT RUN THE PREPROCESSOR. Two definitions of one name
 *    under `#if defined(_WIN32)` / `#else` are both scanned, though only one
 *    exists in any build. They appear as two candidates and, if they agree
 *    on the corpus, as a "duplicate". Read the guard before believing a
 *    same-name pair — and note that this cuts the useful way too: a pair
 *    like that DISAGREEING is a real cross-platform divergence.
 *  - A "NO DUPLICATES" RESULT IS SCOPED TO THE FINGERPRINTABLE SUBSET. It
 *    says nothing about the rest of the tree, which is most of the tree.
 *  - IT DOES NOT KNOW WHAT CODE IS FOR. Two functions that agree on every
 *    input may still be deliberately separate (a consensus-sealed copy, a
 *    platform variant, a boundary between two bounded contexts). Merging is
 *    a human architecture decision; this tool only says "these two agree".
 *
 * The one thing it is designed to be trustworthy about is the direction of
 * its errors: it fails CLOSED. It would rather exclude a fingerprintable
 * function than fingerprint an impure one, because an unstable fingerprint
 * poisons the whole index while a missing one only shrinks it.
 */

#ifndef ZCL_FINGERPRINT_H
#define ZCL_FINGERPRINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FP_MAX_NAME    128
#define FP_MAX_PATH    256
#define FP_MAX_TYPE     96
#define FP_MAX_PARAMS    8
#define FP_MAX_SHAPE   320

/* Why a function is not a fingerprint candidate. Order is report order.
 * EVERY scanned function definition lands in exactly one of these, so the
 * coverage number and its breakdown are a partition, not a sample. */
#define FP_VERDICT_TABLE(X)                                                  \
    X(CANDIDATE,             "candidate")                                    \
    X(SELF_EXCLUDED,         "belongs to the fingerprint tool itself")       \
    X(STATIC_LINKAGE,        "file-local in an unincludable unit")           \
    X(NO_PROTOTYPE,          "no header prototype, unit not includable")     \
    X(VARIADIC,              "variadic parameter list")                      \
    X(FUNCTION_POINTER,      "takes, returns or calls a function pointer")   \
    X(UNSUPPORTED_PARAM,     "parameter shape not synthesisable")            \
    X(UNSUPPORTED_RETURN,    "return shape not observable")                  \
    X(NO_OBSERVABLE_OUTPUT,  "no return value and no output parameter")      \
    X(FUNCTION_STATIC,       "declares a function-static or volatile object")\
    X(IMPURE_GLOBAL,         "reads or writes a mutable file-scope object")  \
    X(UNRESOLVED_CALL,       "calls something the scanner cannot resolve")   \
    X(CLOSURE_TOO_DEEP,      "callee closure exceeded the analysis bound")

enum fp_verdict {
#define FP_VERDICT_ENUM(id_, text_) FP_V_##id_,
    FP_VERDICT_TABLE(FP_VERDICT_ENUM)
#undef FP_VERDICT_ENUM
    FP_V_COUNT
};

const char *fp_verdict_text(enum fp_verdict v);

/* The synthesisable parameter/return shapes. Deliberately narrow: scalars
 * and fixed-size buffers, which is where derivation, codec and crypto code
 * lives. Widening this is how coverage grows; every widening must keep the
 * generated call SOUND, not merely compiling. */
enum fp_kind {
    FP_K_VOID = 0,
    FP_K_SCALAR,      /* integer, bool, char, or an in-tree enum */
    FP_K_CSTR_IN,     /* const char * — a generated NUL-terminated string */
    FP_K_BUF_IN,      /* const T * with an adjacent length parameter */
    FP_K_ARR_IN,      /* const T name[K] — extent evident in the signature */
    FP_K_LEN,         /* the length parameter that binds a FP_K_BUF_IN */
    FP_K_OBJ_IN,      /* const struct/union * — pattern-filled input object */
    FP_K_OUT_SCALAR,  /* T * — a scalar written by the callee */
    FP_K_OUT_ARR,     /* T name[K] — a fixed array written by the callee */
    FP_K_OUT_OBJ,     /* struct/union * — an object written by the callee */
    FP_K_CSTR_OUT     /* const char * return — the pointed-to text is hashed */
};

struct fp_param {
    enum fp_kind kind;
    char type_text[FP_MAX_TYPE];  /* exact C text used to declare the local */
    char elem_text[FP_MAX_TYPE];  /* element type for buffers and arrays */
    unsigned width;               /* scalar width in bytes (0 when unknown) */
    unsigned count;               /* array extent / generated buffer length */
    int pair;                     /* index of the bound length param, or -1 */
    bool is_signed;
};

struct fp_candidate {
    char name[FP_MAX_NAME];
    char def_path[FP_MAX_PATH];
    int  def_line;
    char include[FP_MAX_PATH];    /* what the harness must #include */
    /* True when `include` names the DEFINING TRANSLATION UNIT rather than a
     * header — the only way to call a file-local function. It changes the
     * emitted TU (the unit is included first, ahead of everything the probe
     * scaffolding needs, so its own feature macros still take effect) and it
     * changes how a link failure is attributed: a `static` can never be an
     * undefined reference, so a source-included candidate is only ever
     * blamed through the object file it landed in. */
    bool via_source;
    char group[64];               /* lib/<mod>, app/<shape>, core, … */
    char shape_text[FP_MAX_SHAPE];/* canonical, name-blind shape string */
    uint64_t shape;               /* hash of shape_text; seeds the corpus */
    struct fp_param ret;
    struct fp_param param[FP_MAX_PARAMS];
    int n_params;
};

/* ── Index lifecycle ── */
struct fp_index;

/* Scan the listed repo-relative source files (a `git ls-files` list) and
 * build the symbol/body/macro tables. Returns NULL on hard failure. */
struct fp_index *fp_index_build(const char *root, const char *const *files,
                                size_t n_files);
void fp_index_free(struct fp_index *ix);

/* How many function DEFINITIONS the scan found. This is the denominator of
 * the coverage number. */
size_t fp_index_function_count(const struct fp_index *ix);

/* Turn the source-inclusion route off, so only functions reachable through a
 * header are selected. It exists to MEASURE: run the same tree twice and the
 * difference is exactly what including defining units bought and cost, on one
 * machine, in one build, with nothing else changed. Default is on. */
void fp_index_allow_source_route(struct fp_index *ix, bool on);

/* Judge every scanned definition. Fills `out` with the candidates (up to
 * `cap`) and `tally` with the per-verdict counts (FP_V_COUNT entries).
 * Returns the candidate count, or -1 on error. */
long fp_index_select(struct fp_index *ix, struct fp_candidate *out, size_t cap,
                     size_t *tally);

/* The identifiers most often responsible for one exclusion verdict, most
 * frequent first. An exclusion bucket is only a number; this is what turns it
 * into a work item, because the commonest unresolved call target is either
 * the next entry the pure-primitive allowlist is missing or a real impurity
 * worth knowing about. Fills up to `cap` rows and returns the count. Valid
 * only after fp_index_select. */
int fp_index_top_causes(struct fp_index *ix, enum fp_verdict v,
                        char (*name)[FP_MAX_NAME], size_t *count, int cap);

/* ── Harness generation ── */

/* Write the generated probe translation units, the registry header and the
 * driver main into `work_dir`. `groups_out` receives the number of probe TUs
 * written. `disabled` (may be NULL) is one byte per candidate; a non-zero
 * byte emits the probe as a stub, which is how a probe that failed to
 * compile is dropped without disturbing any other probe's index. */
bool fp_emit_harness(const struct fp_candidate *cands, size_t n_cands,
                     const char *work_dir, const unsigned char *disabled,
                     size_t *groups_out);

/* Which emitted group a candidate landed in (groups are contiguous runs of
 * candidates sharing a `group` string). */
size_t fp_emit_group_of(const struct fp_candidate *cands, size_t n_cands,
                        size_t index);

#endif /* ZCL_FINGERPRINT_H */
