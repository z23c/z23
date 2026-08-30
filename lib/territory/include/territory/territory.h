/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * territory — a GENERATED inventory of one module of this tree.
 *
 * ── Why this exists ──
 * The tree is larger than any one reader (human or agent) can hold, so
 * readers rebuild what already exists. The cure is not a bigger memory; it is
 * a command that can restate a module's inventory on demand. Every number
 * here is derived, at call time, from artifacts the build already maintains:
 *
 *   config/lib_module_order.def   the SET of lib modules (via the code index's
 *                                 group rows, which paste that same file)
 *   the code index               files, sizes, public symbols, call graph,
 *                                 compiler include edges
 *   the registered test catalog   the proof entry points (passed in as a port,
 *                                 see struct territory_proof_source)
 *
 * There is no hand-maintained table of territories, owners, or symbols in
 * this module. Adding a file, a symbol, or a test group changes the answer
 * without anyone editing anything here. That is the whole point: a table a
 * human must update is a table that goes stale.
 *
 * ── Two different facts about proof, never merged ──
 * ROUTED  — "if you changed this file, which registered group would you run?"
 *           That is the shared-rule router `code tests` answers. It is a
 *           routing answer: it says nothing about whether the group executes
 *           any of the file's code.
 * REACHED — "does a registered test group entry point transitively CALL this
 *           symbol?" That is a call-graph answer over the code index's refs
 *           table, seeded from the registered group entry symbols.
 *
 * A symbol can be linked into a test binary and never called. Those two
 * numbers are reported separately and are never added together.
 *
 * ── What the call graph can and cannot see ──
 * The refs table is built by SOURCE SCANNING, so:
 *   - it is NAME-based; two static functions sharing a name in different
 *     translation units are one node. That OVER-approximates reachability, so
 *     a REACHED verdict is the weaker of the two claims and an UNREACHED
 *     verdict is the stronger one.
 *   - an indirect call (a function pointer parked in a dispatch table) is not
 *     a call edge. A symbol whose only references sit at FILE SCOPE — a
 *     static initializer, an X-macro registry row — is exactly that shape, so
 *     it is reported UNKNOWN rather than being counted as either reached or
 *     unreached. Refusing is the point; folding it into a bucket is how a
 *     tool starts lying.
 */

#ifndef ZCL_TERRITORY_H
#define ZCL_TERRITORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct codeindex;

enum {
    TERRITORY_NAME_MAX  = 64,
    TERRITORY_PATH_MAX  = 256,
    TERRITORY_SYM_MAX   = 128,
    TERRITORY_GROUP_MAX = 64,
};

/* ── ports: the two facts lib/ may not reach up for ─────────────────────
 *
 * The registered test catalog lives in tools/dev and the changed-file router
 * lives in app/controllers. Both sit ABOVE lib/, so this module takes them as
 * ports and the caller (the `code territory` handler) supplies the real
 * implementations. That also lets a test inject a synthetic catalog and prove
 * the UNREACHED verdict is genuinely produced, not merely assumed. */

/* Enumerate the registered proof entry symbols ("test_<group>",
 * "spec_<group>"). Returns NULL past the end. */
typedef const char *(*territory_entry_at_fn)(size_t index, void *user);

struct territory_proof_source {
    territory_entry_at_fn at;
    size_t count;
    void *user;
};

/* The changed-file -> registered-group router (the one `code tests` uses).
 * Writes up to `cap` group names into `out` and returns how many rules
 * matched; 0 means no rule matched this path at all. */
typedef size_t (*territory_route_fn)(const char *path,
                                     char (*out)[TERRITORY_GROUP_MAX],
                                     size_t cap, void *user);

struct territory_router {
    territory_route_fn route;
    void *user;
};

/* ── the reached-symbol set ─────────────────────────────────────────────
 *
 * One forward closure over the call graph from every registered entry point.
 * It is a property of the whole tree, not of one territory, so it is computed
 * once per exact source generation and memoized on disk beside the code index
 * it derives from. */
struct territory_reach_set;

struct territory_reach_stats {
    bool     from_cache;      /* answered from the memo, no walk performed */
    bool     cache_written;   /* this call refreshed the memo */
    bool     truncated;       /* a walk bound was hit: verdicts are UNKNOWN */
    uint64_t seeds;           /* registered entry symbols used as roots */
    uint64_t symbols;         /* distinct symbols in the closure */
    uint64_t steps;           /* callee queries the walk performed */
    uint64_t build_us;        /* wall time of the walk (0 when from_cache) */
};

/* Build or load the reached set. `root` is the checkout the index describes;
 * pass NULL to skip the on-disk memo entirely (always walk). Never returns a
 * partially valid set: on failure it returns NULL and logs. */
struct territory_reach_set *territory_reach_open(
    struct codeindex *ci, const char *root,
    const struct territory_proof_source *src,
    struct territory_reach_stats *stats);

bool territory_reach_contains(const struct territory_reach_set *rs,
                              const char *symbol);
size_t territory_reach_count(const struct territory_reach_set *rs);
void territory_reach_free(struct territory_reach_set *rs);

/* ── the scorecard ──────────────────────────────────────────────────── */

enum territory_reach_verdict {
    TERRITORY_UNREACHED = 0,  /* the closure is complete and excludes it */
    TERRITORY_REACHED   = 1,  /* a registered entry transitively calls it */
    TERRITORY_UNKNOWN   = 2   /* the call graph cannot decide; see reason */
};

/* Why a symbol landed where it did. Printed with the verdict so a reader can
 * check the classification instead of trusting it. */
enum territory_reach_reason {
    TERRITORY_REASON_IN_CLOSURE = 0,   /* reached: in the entry-point closure */
    TERRITORY_REASON_NO_REFS,          /* unreached: nothing references it */
    TERRITORY_REASON_COLD_CALLERS,     /* unreached: every caller is itself
                                        * outside the closure */
    TERRITORY_REASON_FILE_SCOPE_REF,   /* unknown: referenced at file scope
                                        * (dispatch table); indirect calls are
                                        * invisible to a source call graph */
    TERRITORY_REASON_WALK_TRUNCATED    /* unknown: a walk bound was hit */
};

const char *territory_reach_verdict_label(enum territory_reach_verdict v);
const char *territory_reach_reason_label(enum territory_reach_reason r);

struct territory_symbol {
    char name[TERRITORY_SYM_MAX];
    char header[TERRITORY_PATH_MAX];   /* the public header that declares it */
    int  line;
    enum territory_reach_verdict verdict;
    enum territory_reach_reason  reason;
    int  refs;                          /* recorded references, capped */
};

struct territory_file {
    char path[TERRITORY_PATH_MAX];
    char route[TERRITORY_GROUP_MAX];    /* first routed group, or "" */
    bool routed;                        /* a shared rule matched this path */
    int64_t bytes;                      /* -1 when the file could not be stat'd */
};

struct territory_group_use {
    char name[TERRITORY_GROUP_MAX];
    int  files;                         /* files in this territory routed here */
};

struct territory_neighbor {
    char name[TERRITORY_GROUP_MAX];
    int  edges;                         /* include edges counted */
};

enum {
    TERRITORY_MAX_FILES     = 4096,
    TERRITORY_MAX_SYMBOLS   = 4096,
    TERRITORY_MAX_GROUPS    = 64,
    TERRITORY_MAX_NEIGHBORS = 64,
};

struct territory_report {
    char name[TERRITORY_NAME_MAX];
    char kind[16];
    char purpose[192];
    bool found;

    /* what it owns */
    int      file_count;         /* files stamped with exactly this group */
    int      header_count;
    int      source_count;
    int64_t  bytes;
    bool     files_truncated;
    struct territory_file files[TERRITORY_MAX_FILES];

    /* what proves it (ROUTED — a routing fact, not an execution fact) */
    int  group_count;
    struct territory_group_use groups[TERRITORY_MAX_GROUPS];
    int  files_unrouted;
    bool groups_truncated;

    /* what proves it (REACHED — an execution fact over the call graph) */
    int  public_symbols;         /* extern functions declared in public headers */
    int  reached;
    int  unreached;
    int  unknown;
    int  public_types;           /* structs/typedefs/enums: not callable */
    int  public_macros;          /* macros: not callable */
    /* The blind spot in the number above, counted rather than hidden. The
     * code index attributes a function declaration only at file scope, so a
     * header that wraps its API in `extern "C" { … }` contributes ZERO
     * functions — its whole public surface is invisible to public_symbols. A
     * territory reporting few or no public functions is therefore not
     * necessarily a territory with little public surface, and these two
     * counts are what tell the two apart. */
    int  headers_without_functions;
    int  headers_extern_c;
    bool symbols_truncated;
    struct territory_symbol symbols[TERRITORY_MAX_SYMBOLS];

    /* what it depends on / what depends on it */
    int  deps_out_count;
    struct territory_neighbor deps_out[TERRITORY_MAX_NEIGHBORS];
    int  deps_in_count;
    struct territory_neighbor deps_in[TERRITORY_MAX_NEIGHBORS];
    bool deps_truncated;
    bool deps_available;         /* false when the index holds no include edges */

    struct territory_reach_stats reach;

    /* What this call cost, reported rather than claimed. A reader who thinks
     * a number looks wrong can see how much work produced it. */
    uint64_t owns_us;      /* file rows + stat() for size */
    uint64_t routed_us;    /* the shared-rule router over every file */
    uint64_t symbols_us;   /* public symbol tables + reach classification */
    uint64_t deps_us;      /* include edges, both directions */
    uint64_t index_lookups; /* file->group index queries actually performed */
};

/* Every territory the tree declares, in index order. These are the code
 * index's group rows, which are themselves pasted from
 * config/lib_module_order.def and the app-shape list — no second list. */
int territory_list(struct codeindex *ci, char (*out)[TERRITORY_NAME_MAX],
                   int cap);

/* Build one territory's scorecard. `root` is the checkout root (used for file
 * sizes and for the reached-set memo). `rs` may be NULL, in which case every
 * symbol is reported UNKNOWN/WALK_TRUNCATED rather than guessed. `router` may
 * be NULL, in which case no file is reported as routed. The report is heap
 * allocated; free it with territory_report_free(). */
struct territory_report *territory_scorecard(
    struct codeindex *ci, const char *root, const char *name,
    const struct territory_reach_set *rs,
    const struct territory_router *router);

void territory_report_free(struct territory_report *r);

/* ── The general's brief ──────────────────────────────────────────────────
 *
 * A GENERAL GRANTS NO AUTHORITY. This is worth spelling out because the word
 * invites the opposite reading, and because a future helpful change here
 * would break the project's oldest rule.
 *
 * Z23's standing rule is "no referee, no authority — everyone runs a full
 * node." Nothing below approves, gates, permits, or blocks anything. A brief
 * is a REPORT: it says what a territory contains and how much of that is
 * proven, so that whoever is about to work there — person or agent — acts on
 * the tree's real inventory instead of a remembered one. It confers no
 * ownership, no review right, and no veto. It is not consulted by any code
 * path that decides. metaverse_grant_check() remains the only answer to what
 * anything is allowed to do, and no call into this header may ever appear on
 * that path. If you find yourself adding an "approved" field, a signer, or a
 * caller that branches on a brief, stop: that is a referee, and a referee is
 * the thing this project refuses.
 *
 * Nothing here is stored. There is no persona file, no owners table, no
 * per-territory prose. Every field is regenerated from the code index, the
 * registered test catalog, the shared impact router, and the lint gate
 * wiring, on every call. A written brief goes stale exactly the way a
 * MAINTAINERS file goes stale, and staleness is the defect being cured.
 *
 * A territory's "personality" is its invariants and refusals, and those are
 * already in the tree as lint gates and their baseline ledgers. They are
 * derived (territory_gates_*), never written down here.
 */

/* ── refuses: the gates that bind a territory ────────────────────────────
 *
 * Derived from tools/lint/run_lint.sh's gate_command() case table — the one
 * place a gate must be wired to run — plus each gate script's own text and
 * the baseline ledgers that name files.
 *
 * Exactly ONE of the three buckets is a positive fact:
 *   BINDS         the gate's script text names a path under this territory, or
 *                 a baseline ledger has a row naming a file in it. Evidence
 *                 travels with the row.
 *   UNKNOWN_OTHER the gate names some other territory's paths but not this
 *                 one's.
 *   UNKNOWN_NONE  the gate names no territory path at all.
 *
 * The last two are BOTH unknown, and their names say so. It is tempting to
 * call UNKNOWN_OTHER "scoped elsewhere" — but a gate that scans the whole tree
 * while happening to mention lib/net in a baseline row would then be reported
 * as not binding lib/coins, which is a guess, and a wrong one. Only the first
 * bucket claims anything. The two unknown buckets are kept apart because the
 * distinction is real evidence for a reader, not because one of them is
 * secretly a "no".
 *
 * The unknown total is large on purpose. Most gates scan the whole tree, and
 * saying so is better than a confident wrong list. */
enum territory_gate_bucket {
    TERRITORY_GATE_UNKNOWN_NONE = 0,
    TERRITORY_GATE_BINDS,
    TERRITORY_GATE_UNKNOWN_OTHER,
};

enum { TERRITORY_GATE_NAME_MAX = 64, TERRITORY_MAX_GATES = 256 };

struct territory_refusal {
    char gate[TERRITORY_GATE_NAME_MAX];
    bool named_in_gate;   /* the gate script's own text names this territory */
    int  baseline_rows;   /* ledger rows naming a file in this territory */
};

/* The wiring table, read once and queried per territory. Reading ~165 gate
 * scripts costs real milliseconds; a roll-up over every territory must not
 * pay it 64 times. */
struct territory_gates;

/* `root` is the checkout root; `names`/`count` are the territories to
 * attribute paths to (territory_list()'s output — no second list). Returns
 * NULL only on allocation failure; a missing or unreadable run_lint.sh yields
 * a table whose wiring_found() is false and whose total is 0, so a caller
 * reports "gate wiring not readable" rather than "no gates bind here". */
struct territory_gates *territory_gates_open(
    const char *root, const char (*names)[TERRITORY_NAME_MAX], int count);
void territory_gates_free(struct territory_gates *g);
bool territory_gates_wiring_found(const struct territory_gates *g);
int  territory_gates_total(const struct territory_gates *g);
/* Rows scanned across every baseline ledger, and how many of those rows named
 * no path this code could attribute to a territory. Printed so a reader can
 * see how much of the ledger evidence the method actually used. */
int  territory_gates_baseline_rows(const struct territory_gates *g);
int  territory_gates_baseline_unattributed(const struct territory_gates *g);
uint64_t territory_gates_build_us(const struct territory_gates *g);

/* ── trusts: can someone else re-check a result from these groups? ───────
 *
 * A DECLARED HOLE. The determinism ledger that would answer this is being
 * built on another lane and has not landed. Every group therefore reports
 * UNKNOWN, and the brief prints the count and names the missing source.
 *
 * The field is not omitted while the answer is missing, because a missing
 * field reads as "nothing to worry about", and that would be a lie: an
 * unreproducible test group is exactly the kind of evidence a second person
 * cannot check. When the ledger lands, supply it here — the shape is already
 * the shape a ledger lookup has, so the wiring is a one-line change at the
 * call site and nothing in the brief moves. */
enum territory_trust {
    TERRITORY_TRUST_UNKNOWN = 0,
    TERRITORY_TRUST_REPRODUCIBLE,
    TERRITORY_TRUST_NOT_REPRODUCIBLE,
};

typedef enum territory_trust (*territory_trust_fn)(const char *group,
                                                   void *user);
struct territory_trust_ledger {
    territory_trust_fn lookup;  /* NULL until the ledger lands */
    void *user;
    const char *source;         /* where the answer came from, for the reply */
};

const char *territory_trust_label(enum territory_trust t);

/* ── the brief ───────────────────────────────────────────────────────── */

enum { TERRITORY_MAX_REFUSALS = 64 };

struct territory_brief {
    struct territory_report *report;    /* owns / proves / depends / weak */

    /* refuses — three buckets that partition the wired gates. Only
     * gates_binding is a claim; the other two are both "cannot tell", kept
     * apart because the difference is evidence a reader can use. */
    bool gate_wiring_found;
    int  gates_total;
    int  gates_binding;
    int  gates_unknown_named_others;
    int  gates_unknown_named_none;
    int  refusal_count;                 /* rows below, binding gates only */
    bool refusals_truncated;
    struct territory_refusal refuses[TERRITORY_MAX_REFUSALS];

    /* trusts — the declared hole */
    int  trust_reproducible;
    int  trust_not_reproducible;
    int  trust_unknown;
    char trust_source[96];

    /* where the evidence is weakest. unproven == unreached + unknown: public
     * functions no registered test is known to call. Printed next to the
     * inputs so a reader can re-derive it. */
    int  unproven;
    int  unrouted_files;

    uint64_t gates_us;
};

/* Assemble a brief. Takes ownership of nothing; `report` is built internally
 * and freed by territory_brief_free(). `gates` may be NULL (the refuses
 * section then reports the wiring as unreadable rather than empty), and
 * `trust` may be NULL or carry a NULL lookup (every group reports UNKNOWN). */
struct territory_brief *territory_brief_build(
    struct codeindex *ci, const char *root, const char *name,
    const struct territory_reach_set *rs,
    const struct territory_router *router,
    const struct territory_gates *gates,
    const struct territory_trust_ledger *trust);

void territory_brief_free(struct territory_brief *b);

/* ── the roll-up ─────────────────────────────────────────────────────────
 *
 * One page across every territory, ranked by where the evidence is weakest —
 * not by size and not alphabetically. The rank key is `unproven`: public
 * functions that no registered test entry point is known to reach, counting
 * the walk's refusals as unproven rather than as fine. Ties break on
 * unrouted files, then on name so the order is stable.
 *
 * The choice is deliberate. Ranking by unrouted files alone puts lib/test at
 * the top, which is an artifact: a test file routes to no group because it IS
 * the group. Ranking by size puts the biggest territory first whether or not
 * anything is wrong with it. Ranking by unproven public surface answers the
 * question a person actually has — "where is there code nothing calls?" —
 * and the answer survives being asked "would I go there first?". */
struct territory_rank {
    char name[TERRITORY_NAME_MAX];
    int  files;
    int  public_symbols;
    int  reached;
    int  unproven;          /* unreached + unknown */
    int  unreached;
    int  unknown;
    int  unrouted_files;
    int  headers_extern_c;  /* a high count means the number above is a floor */
};

struct territory_rollup {
    int count;                              /* territories scored */
    int scored;                             /* scorecards that built */
    int failed;                             /* scorecards that did not */
    int64_t total_files, total_public, total_reached;
    int64_t total_unreached, total_unknown, total_unrouted;
    int64_t total_headers_extern_c;
    uint64_t build_us;
    /* Scoring every territory means routing every file in the tree, and the
     * shared impact router costs milliseconds per path. The result is a pure
     * function of the sealed source generation, so it is memoized beside the
     * reach closure and verified the same way. `from_cache` says which of the
     * two this particular answer is; the cost is never hidden. */
    bool from_cache;
    bool cache_written;
    struct territory_rank ranks[TERRITORY_MAX_GROUPS * 2];
};

/* Score every territory and rank them. Returns NULL on allocation failure. */
struct territory_rollup *territory_rollup_build(
    struct codeindex *ci, const char *root,
    const struct territory_reach_set *rs,
    const struct territory_router *router);

void territory_rollup_free(struct territory_rollup *r);

#endif /* ZCL_TERRITORY_H */
