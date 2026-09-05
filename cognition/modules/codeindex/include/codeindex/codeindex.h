/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex — an in-binary, hierarchical, token-bounded source-code
 * navigator index for the zclassic23 tree.
 *
 * ── What it is ──
 * A DERIVED store (like contexts/commons/modules/vcs's index.kv) built by scanning the in-tree C
 * source: it records, per symbol, where it is DEFINED and DECLARED, a cleaned
 * one-line signature, its leading doc comment, its enclosing `#ifdef` guard,
 * the group (lib/<mod>, app/<shape>, core, tools, config, …) it belongs to,
 * plus include edges (from build depfiles) and a bounded call-site ref index.
 *
 * ── Ground truth ──
 * The PRIMARY source of truth is IN-TREE SOURCE SCANNING — the release build
 * ships without `-g`, so `nm` yields no line info. Everything here is
 * recomputed from source; nothing is repaired in place ("recompute, never
 * repair"). The store lives at <root>/.codeindex/index.kv (a dedicated
 * single-writer SQLite WAL below the AR layer, beside .git).
 *
 * This header is the QUERY surface. The rebuild / staleness surface is in
 * codeindex_build.h. A LATER lane wires the `code` command branch on top of
 * these calls — do not add commands here.
 */

#ifndef ZCL_CODEINDEX_H
#define ZCL_CODEINDEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Opaque handle. Open lazily rebuilds the store if the source tree changed. */
struct codeindex;

/* ── Result records — flat POD, fixed buffers (mirrors vcs records) ── */

/* A symbol "card": everything needed to render a one-screen answer about a
 * name without opening the file. `kind` is a single char:
 *   'T' func         't' static func
 *   'S' struct/union 'Y' typedef      'E' enum
 *   'M' macro (#define)               'D' data / other top-level decl
 * `partial` is set when the scanner could not confidently extract a clean
 * one-line signature (multiline prototypes, X-macro-wrapped decls, …) and
 * fell back to the raw declaration line — the symbol is still emitted. */
struct ci_symbol {
    char name[128];
    char kind;
    char def_path[256];
    int  def_line;
    char decl_path[256];
    int  decl_line;
    char signature[512];
    char doc[256];
    char guard[128];
    char group[64];
    bool partial;
};

/* Capacity of a file's one-line self-description.
 *
 * SIZED FROM THE CORPUS, NOT GUESSED. At 160 this field truncated real
 * purposes: one full rebuild of this tree cut 16 files, the longest by 95
 * bytes, and every cut emitted a WARN line into whatever stream the caller was
 * reading. The clause a purpose loses first is its END — the part that says
 * what the file is FOR — which is exactly the text a capability search ranks
 * on, so the truncation was not only noisy, it degraded the answer.
 *
 * The number: with the field temporarily raised to 1024 and the whole tree
 * reindexed (2026-08-29), the longest stored purpose measured 260 bytes and
 * exactly one file exceeded 250. 320 clears that maximum by 60 bytes without
 * paying for a kilobyte in every `struct ci_file` array in the tree.
 *
 * The scanner's capture buffer is deliberately LARGER than this field (see
 * CI_FILE_PURPOSE_CAPTURE_MAX), so a purpose that ever outgrows the corpus is
 * cut by zcl_text_fit — which says so — rather than clipped in silence by the
 * capture. Fail loud, never quiet: a returning WARN is the signal to re-measure
 * and raise this, not to widen the capture. */
#define CI_FILE_PURPOSE_MAX 320

/* A source file and the group it maps to. */
struct ci_file {
    char path[256];
    char group[64];
    char purpose[CI_FILE_PURPOSE_MAX];
};

/* A node in the group hierarchy (lib/<mod>, app/<shape>, core, …). */
struct ci_group {
    char path[64];
    char kind[16];
    char parent[64];
    char purpose[160];
};

/* Exact file-kind totals in one verified index generation. c23_files includes
 * tracked fixture inputs because the index must retain their symbols and
 * impact edges. governed_c23_files excludes exact `fixtures` path segments,
 * matching the capability inventory and science corpus; fixture_c23_files
 * makes that projection difference explicit. Registry nodes are
 * behavior-bearing .def files, never counted as C23. */
struct ci_source_file_counts {
    int c23_files;
    int governed_c23_files;
    int fixture_c23_files;
    int registry_nodes;
};

/* A recorded call site. `enclosing` is the name of the function the call site
 * sits inside — the greatest function whose def_line <= ref_line in the same
 * file (C does not nest functions; documented best-effort). Empty string when
 * unattributed (e.g. a reference at file scope). This is the column that turns
 * the flat refs table into a call graph: callees of X are the refs WHERE
 * enclosing == X. Populated by the scan pass (codeindex_scan.c). */
struct ci_ref {
    char callee[128];
    char ref_file[256];
    int  ref_line;
    char enclosing[128];
};

enum ci_search_match {
    CI_SEARCH_MATCH_NAME = 1u << 0,
    CI_SEARCH_MATCH_SIGNATURE = 1u << 1,
    CI_SEARCH_MATCH_PATH = 1u << 2,
    CI_SEARCH_MATCH_DOC = 1u << 3,
};

/* One explained full-index search result. score is a deterministic ranking
 * convenience; the mask says which indexed fields contained the query. */
struct ci_search_hit {
    struct ci_symbol symbol;
    uint32_t match_mask;
    int score;
};

/* ── Lifecycle ── */

/* Open (creating if needed) <root>/.codeindex/index.kv. If the store is
 * missing or the source tree's staleness stamp no longer matches, this
 * rebuilds it before returning. NULL on hard failure. */
struct codeindex *codeindex_open(const char *root);
/* Open with exact SOURCE freshness but without treating compiler depfile
 * movement as staleness. This is only for queries whose answer is derived
 * entirely from source rows (for example code.group); include/dependency
 * queries must use codeindex_open(). A missing store or any source/schema
 * change still triggers the normal deterministic full rebuild. */
struct codeindex *codeindex_open_source_view(const char *root);
/* Open a source-only view whose retrieval projection has also been verified
 * against its sealed logical root. A mismatched projection is fully rebuilt
 * from source before return; unrelated code navigation avoids this bounded
 * full-projection cost. */
struct codeindex *codeindex_open_retrieval_view(const char *root);
/* Open only an already-built, verify-on-read store. This never rebuilds and
 * therefore may describe the immediately preceding source generation. It is
 * for bounded resident overlay queries which scan changed files themselves;
 * callers must not present the handle as a fresh source index. */
struct codeindex *codeindex_open_existing(const char *root);
void codeindex_close(struct codeindex *ci);

/* Exact content root of the source generation this verified handle reads.
 * codeindex_open() has already matched the store's stat-bound freshness root
 * to the checkout, so this is a safe generation key for in-process derived
 * caches. Returns false if the sealed 32-byte metadata record is absent or
 * malformed; it never fabricates an all-zero generation. */
bool codeindex_source_root_sha3(struct codeindex *ci, uint8_t out[32]);

/* The cold-build self-receipt: wall-clock milliseconds and indexed file count
 * of the last FULL deterministic build, sealed by the store itself
 * (meta.build_cold_ms / meta.build_cold_files). Incremental refreshes never
 * rewrite them. Returns false WITHOUT logging when the keys are absent (a
 * store built before the receipt existed) or malformed; both outputs are
 * zeroed in that case. */
bool codeindex_build_cold_ms(struct codeindex *ci, long long *ms_out,
                             long long *files_out);

/* Exact row counts of the published generation. Never rebuilds. */
bool codeindex_table_counts(struct codeindex *ci, int64_t *files,
                            int64_t *symbols, int64_t *refs, int64_t *groups);
/* Per-group file count and indexed-symbol count (`lines`). */
struct ci_group_metric {
    char name[64];
    int64_t files;
    int64_t lines;
};
int codeindex_group_metrics(struct codeindex *ci, struct ci_group_metric *out,
                            int cap);

/* Exact logical root of the groups/files/symbols/refs projection consumed by
 * retrieval. Unlike source_root_sha3, this binds scanner output as well as
 * source identity. A retrieval view verifies it before adoption; snapshot
 * handles may call the current-check below. Because the checksum is stored
 * beside the derived rows, it detects divergence but is not authenticity,
 * evaluator, or acceptance authority against an owner who deliberately
 * rewrites both rows and root. */
bool codeindex_retrieval_projection_root_sha3(struct codeindex *ci,
                                              uint8_t out[32]);
/* Recompute and compare the retrieval projection on this exact bound handle.
 * A successful false result is evidence of logical cache divergence. */
bool codeindex_retrieval_projection_is_current(struct codeindex *ci,
                                               bool *current);

/* Recheck that a source-only reader still describes the checkout generation
 * now present at its root. This never rebuilds or advances the handle. A
 * successful false result is an observed generation change, including an
 * A->B->A byte schedule whose source metadata changed; a failed observation
 * returns false and leaves *current=false. */
bool codeindex_source_view_is_current(struct codeindex *ci, bool *current);

/* ── Queries ── */

/* Exact-name lookup. On a hit fills *out and sets *found=true; verify-on-read
 * rejects a corrupted row (returns found=false). Returns false only on a hard
 * error (never for "not found"). */
bool codeindex_symbol(struct codeindex *ci, const char *name,
                      struct ci_symbol *out, bool *found);

/* Stable-id lookup. Unlike the legacy name lookup, a static-function id
 * (`fn:static:<repo-path>:<name>`) resolves that exact definition, so equal
 * static names in different translation units cannot collide. */
bool codeindex_symbol_by_id(struct codeindex *ci, const char *id,
                            struct ci_symbol *out, bool *found);

/* Ranked substring search over symbol names: exact match ranks first, then
 * prefix, then substring; ties broken by name then def_path for determinism.
 * Fills up to `cap` rows in `out`, returns the count (>=0), -1 on error. */
int codeindex_find(struct codeindex *ci, const char *query,
                   struct ci_symbol *out, int cap);

/* Ranked literal substring search over names, signatures, definition/
 * declaration paths, and indexed documentation. Exact/prefix/name matches
 * precede signature, path, and doc matches; ties are byte-stable. */
int codeindex_search_text(struct codeindex *ci, const char *query,
                          struct ci_search_hit *out, int cap);

/* Rank indexed files from a plain-language story with the shared BM25
 * retrieval engine. The document for each file is its path, group, purpose,
 * and indexed symbol names/signatures/docs/guards. Results are deterministic
 * for one verified code-index generation. `cap` is the observation bound;
 * `truncated` is true when more positive-score files exist. */
struct ci_story_hit {
    char path[256];
    double score;
};
int codeindex_search_story(struct codeindex *ci, const char *query,
                           struct ci_story_hit *out, int cap,
                           size_t *corpus_files, bool *truncated);

/* Call sites referencing `callee`, ordered by (ref_file, ref_line). Fills up
 * to `cap` rows, returns count (>=0), -1 on error. */
int codeindex_refs(struct codeindex *ci, const char *callee,
                   struct ci_ref *out, int cap);

/* File → its group/purpose. */
bool codeindex_file(struct codeindex *ci, const char *path,
                    struct ci_file *out, bool *found);

/* The full group hierarchy, ordered by path. */
int codeindex_groups(struct codeindex *ci, struct ci_group *out, int cap);

/* Files that belong to `group` (e.g. "app/services", "core/modules/net"), ordered by
 * path. Fills up to `cap` rows, returns the count (>=0), -1 on error. */
int codeindex_files_in_group(struct codeindex *ci, const char *group,
                             struct ci_file *out, int cap);

/* Every indexed file, sorted by repo-relative path. Pages keep caller memory
 * bounded independently of corpus size. */
int codeindex_file_count(struct codeindex *ci);
int codeindex_files_page(struct codeindex *ci, int offset,
                         struct ci_file *out, int cap);

/* Count files in `group`. When `recursive` is false, only files stamped with
 * EXACTLY this group; when true, also every descendant group (so "lib" or "app"
 * aggregates its child modules/shapes). Returns the count (>=0), -1 on error. */
int codeindex_count_files_in_group(struct codeindex *ci, const char *group,
                                   bool recursive);

/* Count the two admitted source-node kinds without walking the checkout. */
bool codeindex_source_file_counts(struct codeindex *ci,
                                  struct ci_source_file_counts *out);

/* The symbol table of one file: symbols DEFINED in it (for a .c) or DECLARED in
 * it (for a header), definitions first then source order. Fills up to `cap`
 * rows, returns count (>=0), -1 on error. */
int codeindex_symbols_in_file(struct codeindex *ci, const char *path,
                              struct ci_symbol *out, int cap);

/* In-tree include dependencies of `path`, ordered by dep path. Each out[i] is a
 * NUL-terminated repo-relative path (up to 255 bytes). Fills up to `cap` rows,
 * returns count (>=0), -1 on error.
 *
 * AVAILABILITY WARNING — a zero here is not always "this file includes
 * nothing". The edges are compiler depfile rows, and a depfile is keyed on the
 * TRANSLATION UNIT it compiled: every edge is (that .c file -> a prerequisite).
 * A header is never the compiled unit, so this query returns zero rows for
 * EVERY header in the tree, unconditionally, forever — a structural blind spot
 * that no truncation flag can ever report. Ask
 * codeindex_path_is_translation_unit() and codeindex_include_edge_count()
 * BEFORE presenting a zero as a complete answer. */
int codeindex_includes_of_file(struct codeindex *ci, const char *path,
                               char (*out)[256], int cap);

/* Ordered bounded page of the same compiler-depfile prerequisites. `offset`
 * is a zero-based row offset in dep-path order. A short page (including zero)
 * is the exact end witness; callers that need complete coupling evidence must
 * page instead of treating a full fixed-cap result as complete. */
int codeindex_includes_of_file_page(struct codeindex *ci, const char *path,
                                    int offset, char (*out)[256], int cap);

/* Total include edges the index holds. ZERO means the depfile graph was absent
 * when the index was built (a fresh clone, or after `make clean`) — every
 * include question is then UNANSWERED, not answered with zero. Returns the
 * count (>=0), -1 on error. */
int64_t codeindex_include_edge_count(struct codeindex *ci);

/* True iff `path` names a compiled translation unit (a `.c`), the only file
 * class for which codeindex_includes_of_file can return a non-empty forward
 * answer. Pure: no I/O, no index. */
bool codeindex_path_is_translation_unit(const char *path);

/* Render a bounded, human-readable card for `name` into `buf` (NUL-terminated,
 * never exceeds `cap`). Returns the number of bytes written (excluding NUL),
 * or -1 on error / not found. */
int codeindex_render_card(struct codeindex *ci, const char *name,
                          char *buf, size_t cap);

/* ── Call-graph queries (WF4 code-capsule) ──────────────────────────────
 *
 * Built on the `enclosing` column above (populated by the scan pass). */

/* Callers of `name`: the call sites referencing it, each with `enclosing`
 * filled (the function the call sits in). Ordered by (ref_file, ref_line).
 * Fills up to `cap` rows, returns count (>=0), -1 on error. Equivalent to
 * codeindex_refs but with the enclosing attribution guaranteed populated. */
int codeindex_callers(struct codeindex *ci, const char *name,
                      struct ci_ref *out, int cap);

/* Callees of `enclosing_name`: the distinct symbols referenced from inside it
 * (refs WHERE enclosing == enclosing_name). Ordered by (ref_file, ref_line).
 * Fills up to `cap` rows, returns count (>=0), -1 on error. */
int codeindex_callees(struct codeindex *ci, const char *enclosing_name,
                      struct ci_ref *out, int cap);

/* Identity-aware variants. Static functions are restricted to their
 * definition file; externally linked symbols retain name-wide behavior. */
int codeindex_callers_for_symbol(struct codeindex *ci,
                                 const struct ci_symbol *symbol,
                                 struct ci_ref *out, int cap);
int codeindex_callees_for_symbol(struct codeindex *ci,
                                 const struct ci_symbol *symbol,
                                 struct ci_ref *out, int cap);

/* Linkage-aware stable identity for `name`, computed from existing fields:
 * "fn:static:<path>:<name>" for a static function, "fn:external:<name>" for an
 * external one (name-based lookup is untouched). Writes a NUL-terminated id
 * into `buf` (capacity `cap`). Returns the length written (excluding NUL), or
 * -1 on error / not found. */
int codeindex_symbol_id(struct codeindex *ci, const char *name,
                        char *buf, size_t cap);
int codeindex_symbol_record_id(const struct ci_symbol *symbol,
                               char *buf, size_t cap);

/* ── Impact-closure query (proof-DAG from symbol closure, F3) ───────────
 *
 * Given a set of changed FILES, compute the changed symbols (every symbol the
 * store attributes to one of those files — a .c's definitions, a header's
 * declarations), then walk the bounded REVERSE-caller closure (callers of
 * callers, via refs.enclosing) up to `max_depth` levels, and return the set of
 * impacted FILES: every file that transitively references a changed symbol
 * PLUS the changed files themselves. This is the file-level "blast radius" of a
 * change, derived from the call graph rather than a path glob.
 *
 * Output is DETERMINISTIC (unique, sorted by path) and filled up to `cap` rows.
 * *truncated is set true iff the closure hit an internal size cap, a per-query
 * fan-out cap, or overflowed `cap` — i.e. the returned set may be INCOMPLETE,
 * so a caller building a test plan MUST fall back to path-only rather than
 * trust a silently-partial set. `max_depth <= 0` selects CI_CLOSURE_DEFAULT_DEPTH
 * (depth exhaustion is a normal bound, NOT truncation: the file set returned for
 * the walked depth is complete). Returns the file count (>=0), -1 on hard error.
 * `changed_files` is an array of NUL-terminated repo-relative paths. */
#define CI_CLOSURE_DEFAULT_DEPTH 8
/* One authority for the largest file set the impact engine can prove. A
 * consumer should size its bounded result buffer from its verified corpus,
 * capped here, rather than impose a smaller unrelated ceiling that turns a
 * complete graph into an artificial truncation. */
#define CI_IMPACT_CLOSURE_MAX_FILES 20000
int codeindex_impact_closure(struct codeindex *ci,
                             const char (*changed_files)[256], int n_changed,
                             int max_depth,
                             char (*out)[256], int cap, bool *truncated);

/* Conservative resident variant: union the existing store's symbols for each
 * changed file with symbols scanned from its current bytes before walking
 * callers. Other files are unchanged within the caller's guarded source epoch,
 * so their reverse edges remain the exact caller authority. */
int codeindex_impact_closure_overlay(
    struct codeindex *ci, const char *root,
    const char (*changed_files)[256], int n_changed, int max_depth,
    char (*out)[256], int cap, bool *truncated);

/* Proof-selection variant: record a caller file, then ask whether that file is
 * a terminal evidence owner. Terminal callers are not traversed through into
 * generic dispatchers; non-terminal callers retain the ordinary reverse walk.
 * The callback does not run on the changed seed itself. */
typedef bool (*codeindex_impact_terminal_fn)(const char *path, void *user);
int codeindex_impact_closure_with_terminal(
    struct codeindex *ci, const char (*changed_files)[256], int n_changed,
    int max_depth, codeindex_impact_terminal_fn terminal, void *terminal_user,
    char (*out)[256], int cap, bool *truncated);
int codeindex_impact_closure_overlay_with_terminal(
    struct codeindex *ci, const char *root,
    const char (*changed_files)[256], int n_changed, int max_depth,
    codeindex_impact_terminal_fn terminal, void *terminal_user,
    char (*out)[256], int cap, bool *truncated);

/* One entry point covering both variants above plus an early exit. `root` is
 * NULL for the store-only walk and a repo root for the overlay walk. When
 * `stop_at_truncation` is set the traversal returns as soon as any bound
 * fires: a caller whose answer to "the closure is bounded" is a FIXED one —
 * such as "then run every test group" — learns nothing further from paging
 * the rest of a very large frontier, and paging it can cost minutes. The
 * returned set is then a prefix of the walk and *truncated is true, which is
 * exactly what such a caller already treats as "do not trust this set". */
int codeindex_impact_closure_bounded(
    struct codeindex *ci, const char *root,
    const char (*changed_files)[256], int n_changed, int max_depth,
    codeindex_impact_terminal_fn terminal, void *terminal_user,
    char (*out)[256], int cap, bool *truncated, bool stop_at_truncation);

/* ── Forward (callee) input-closure query — the content-addressed test cache
 * key input (symmetric mirror of codeindex_impact_closure) ──────────────
 *
 * Given a ROOT SYMBOL (e.g. a test entry point "test_<name>"), compute the set
 * of in-tree source FILES whose byte content can change the behavior reachable
 * from that symbol: every file that DEFINES a symbol transitively reachable via
 * the FORWARD callee graph (refs.enclosing walk), PLUS every in-tree header
 * those definition files include (compiler-depfile edges — sound + complete for
 * the include dimension). This is the INPUT closure a caller content-addresses
 * to decide whether re-running the symbol is necessary.
 *
 * Where codeindex_impact_closure answers "who is impacted when X changes"
 * (reverse callers, a conservative test-selection superset), this answers "what
 * does X depend on" (forward callees, the input set). The two walk the same
 * call graph in opposite directions and share its one intrinsic limit: an edge
 * that source scanning never recorded (an indirect/function-pointer/dlopen
 * dispatch) is invisible to both. A SOUNDNESS-sensitive caller (a result cache)
 * MUST therefore treat a *truncated result as UNCACHEABLE and MUST back the
 * cache with a cold-audit path that never trusts it — see tests/harness/src/test_cache.c.
 *
 * Output is DETERMINISTIC (unique, sorted by path) and filled up to `cap` rows.
 * *truncated is set true iff the closure hit an internal size cap, a per-symbol
 * callee fan-out cap, overflowed `cap`, OR the depth ceiling was reached with
 * the frontier still non-empty — i.e. the returned set may be INCOMPLETE.
 * *root_found (may be NULL) is set false iff root_symbol is not a known in-tree
 * symbol (then the closure is empty — the caller cannot bound the inputs, so it
 * too is UNCACHEABLE). Returns the file count (>=0), -1 on hard error. */
int codeindex_forward_closure(struct codeindex *ci, const char *root_symbol,
                              char (*out)[256], int cap,
                              bool *truncated, bool *root_found);

/* The include graph's own inventory: how many compiler depfiles it was built
 * from, and the newest modification time among them (nanoseconds). Both come
 * from the exact traversal the graph itself uses, so a caller asking "does the
 * graph exist?" or "is my input newer than the graph?" gets the graph's answer
 * rather than its own.
 *
 * Walk build/ yourself and you are writing a second traversal of a layout with
 * real rules — retained compile epochs, pre-epoch leftovers, the pointer that
 * names the live generation — and the two copies drift the moment the layout
 * moves. They already did: a private copy of this walk kept the result cache
 * reporting an ABSENT include graph long after the graph was rebuilt.
 *
 * A count of 0 means ABSENT (fresh tree, or nothing current to read), which is
 * a legitimate state and not an error. Returns false on I/O failure, with both
 * outputs zeroed. */
bool codeindex_depfile_graph(const char *root, size_t *out_count,
                             int64_t *out_newest_mtime_ns);

/* ── Reverse INCLUDE closure — the dimension the call graph cannot see ───
 *
 * codeindex_impact_closure walks CALL edges. A macro-only header, a typedef,
 * an enum, a constant, and an X-macro registry (`*.def`) have no call edges at
 * all, so their blast radius in that walk is empty even though every
 * translation unit that reads them recompiles and can change behavior. This
 * query answers the other question: which in-tree files did the compiler read
 * `path` while building?
 *
 * The edges come from the compiler's own depfiles, not from re-parsing
 * `#include` lines — the build already resolved every search path and macro
 * guard, and a depfile's prerequisite list is TRANSITIVELY FLATTENED (it names
 * every byte the translation unit read, however many headers deep). So a single
 * equality probe over that edge set is already the transitive reverse closure
 * over translation units; there is no second walk to do and no depth to bound.
 *
 * Availability is a first-class outcome, NOT an empty result. Depfiles exist
 * only after a build, so a fresh clone has no include graph at all — reporting
 * that as "nothing depends on this header" is the exact failure mode this
 * query exists to remove. *dim distinguishes the three:
 *   COMPLETE    — the graph was present and the full dependent set fit `cap`
 *   TRUNCATED   — the graph was present, `cap` could not hold the answer
 *   UNAVAILABLE — the index holds no include edges; the question is unanswered
 * Returns the dependent count (>=0), -1 on hard error. `out` is sorted and
 * unique. */
enum codeindex_include_dim {
    CODEINDEX_INCLUDE_DIM_COMPLETE = 0,
    CODEINDEX_INCLUDE_DIM_TRUNCATED,
    CODEINDEX_INCLUDE_DIM_UNAVAILABLE
};

int codeindex_reverse_includes(struct codeindex *ci, const char *path,
                               char (*out)[256], int cap,
                               enum codeindex_include_dim *dim);

/* Stable label for a reverse-include availability verdict. Deliberately shares
 * its wording with tests/harness/include/test/testcache.h's reason labels
 * ("closure-truncated", "no-include-graph") so a plan and the result cache
 * never describe the same incompleteness with two different words. */
const char *codeindex_include_dim_label(enum codeindex_include_dim dim);

#endif /* ZCL_CODEINDEX_H */
