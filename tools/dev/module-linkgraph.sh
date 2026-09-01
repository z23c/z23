#!/usr/bin/env bash
# module-linkgraph — the REAL module dependency graph, measured from the
# linker's own view (symbols), not from #include lines.
#
# Why symbols and not includes: the include graph is the COMPILE order; the
# symbol graph is the LINK order, and they differ. A file can reach into
# another module through a bare `extern` declaration with no #include at all
# (engine/modules/storage/src/catalog_completeness.c does exactly this, on purpose).
# Depfiles cannot see that edge. `nm` over the compiled objects can, because
# the reference is an undefined symbol in one object and a defined symbol in
# another.
#
# Method: for every object in the active compile epoch, split `nm -A -g` into
#   defined   (type != 'U'/'w')  -> that object's module OWNS the symbol
#   undefined (type == 'U'/'w')  -> that object's module REFERENCES it
# then join on the symbol name and drop intra-module pairs. What is left is
# exactly "module A's code cannot link without module B".
#
# Modules are navigator groups (same mapping as ci_group_for_path):
#   lib/<mod>  app/<shape>  domain/<ctx>  core  config  tools  adapters  root
#
# Usage:
#   tools/dev/module-linkgraph.sh [--summary|--edges|--modules|--fas]
#                                 [--obj-dir DIR | --obj-root ROOT]
#
#   --summary   (default) one line per module->module edge:
#                 <from> -> <to> <TAB> <refcount> <TAB> sym,sym,...
#   --edges     one line per individual reference (machine-readable):
#                 <from_module> <TAB> <to_module> <TAB> <symbol> <TAB> <from_file>
#   --modules   one line per module that has at least one object
#   --fas       the lib/ subgraph's cycle structure: strongly-connected
#               components plus the EXACT minimum feedback arc set — the
#               fewest edges that must run backward under any ranking. This is
#               what makes engine/composition/lib_module_order.def's "5 back edges is
#               optimal" claim checkable rather than asserted; re-run it after
#               any change to the graph. Scoped to lib/ (minus lib/test)
#               because that is precisely what the .def ranks.
#   --obj-dir   measure exactly this directory of objects
#   --obj-root  measure only this object ROOT (its newest epoch, else the root
#               itself), instead of searching the preference list below
#
# Object directory selection, in precedence order:
#   1. --obj-dir DIR / --obj-root ROOT  (mutually exclusive)
#   2. $ZCL_LINKGRAPH_OBJ_DIR           (only when neither flag was given)
#   3. the OBJ_ROOT_PREFERENCE search below
# Within a root, the active epoch is the epochs/ subdir holding the newest
# object; a root with no epochs/ tree is scanned directly.
#
# WHICH TREE YOU MEASURE CHANGES THE ANSWER, so callers that compare against a
# stored baseline must pin one. The trees are compiled differently: build/obj
# is -flto=auto (production), while the test roots are -O3 non-LTO with
# -DZCL_TESTING, which both keeps references LTO would have resolved away and
# compiles testing-only code paths. Measured 2026-07-25 the test tree carried
# 3 lib->app references the production tree does not have at all. So a
# baseline seeded from one tree reports phantom violations against another —
# that is not drift to reconcile, it is a category error. check-lib-module-order
# passes --obj-root build/obj for exactly this reason; see the
# "measured-from-tree" header in tools/scripts/lib_module_order_baseline.txt,
# which the gate asserts against the root it actually measured.
set -euo pipefail

cd "$(dirname "$0")/../.."

MODE=summary
# Explicit flags only. $ZCL_LINKGRAPH_OBJ_DIR is folded in AFTER parsing so an
# exported env var never collides with an explicitly passed --obj-root.
OBJ_DIR=""
OBJ_ROOT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --summary) MODE=summary ;;
        --edges)   MODE=edges ;;
        --modules) MODE=modules ;;
        --fas)     MODE=fas ;;
        --obj-dir) shift; OBJ_DIR="${1:-}" ;;
        --obj-root) shift; OBJ_ROOT="${1:-}" ;;
        -h|--help) sed -n '2,51p' "$0"; exit 0 ;;
        *) echo "module-linkgraph: unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

if [ -n "$OBJ_DIR" ] && [ -n "$OBJ_ROOT" ]; then
    echo "module-linkgraph: --obj-dir and --obj-root are mutually exclusive" >&2
    exit 2
fi

# Env fallback: only when neither flag was given.
if [ -z "$OBJ_DIR" ] && [ -z "$OBJ_ROOT" ]; then
    OBJ_DIR="${ZCL_LINKGRAPH_OBJ_DIR:-}"
fi

# Object-root preference, most authoritative first: the production compile tree,
# then the release/fast/asan test trees, then the dev tree — the Makefile's
# OBJ_ROOT / TEST_REL_OBJ_ROOT / TEST_FAST_OBJ_ROOT / TEST_ASAN_OBJ_ROOT /
# DEV_OBJ_ROOT. A fixed order (rather than "whatever is newest") keeps the
# reported graph stable when several profiles are warm. This fall-through is
# for INTERACTIVE use — "show me the graph from whatever is warm". Anything
# comparing against a stored baseline must pass --obj-root instead.
OBJ_ROOT_PREFERENCE="build/obj build/test-rel-obj build/test-obj build/test-asan-obj build/dev-obj"

pick_obj_dir() {
    local root newest
    for root in ${OBJ_ROOT:-$OBJ_ROOT_PREFERENCE}; do
        if [ -d "$root/epochs" ]; then
            # Active epoch = the one holding the most recently written object.
            newest=$(find "$root/epochs" -mindepth 1 -maxdepth 1 -type d \
                     -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
            if [ -n "$newest" ] && [ -n "$(find "$newest" -name '*.o' -type f -print -quit)" ]; then
                printf '%s\n' "$newest"
                return 0
            fi
        fi
        if [ -d "$root" ] && [ -n "$(find "$root" -name '*.o' -type f -print -quit)" ]; then
            printf '%s\n' "$root"
            return 0
        fi
    done
    return 1
}

if [ -z "$OBJ_DIR" ]; then
    if ! OBJ_DIR=$(pick_obj_dir); then
        if [ -n "$OBJ_ROOT" ]; then
            echo "module-linkgraph: no compiled objects under $OBJ_ROOT." >&2
        else
            echo "module-linkgraph: no compiled objects found." >&2
        fi
        echo "  Run 'make build-only -j\$(nproc)' first." >&2
        exit 1
    fi
fi

if [ ! -d "$OBJ_DIR" ]; then
    echo "module-linkgraph: object dir not found: $OBJ_DIR" >&2
    exit 1
fi

# A root-selected production epoch can retain an object after its source was
# deleted or moved: `make` knows not to link it, but `find *.o` used to feed it
# to this graph forever. That produced a false architectural edge after
# log_throttle.c moved from platform/modules/util to platform/modules/support. Filter root scans through
# the same repo-relative `.o` -> `.c` mapping used below. An explicit --obj-dir
# remains an unfiltered diagnostic seam so synthetic gate fixtures need not
# manufacture a source checkout beside their objects.
list_objects() {
    local obj rel src
    while IFS= read -r -d '' obj; do
        if [ -n "$OBJ_ROOT" ]; then
            rel="${obj#"$OBJ_DIR"/}"
            src="${rel%.o}.c"
            [ -f "$src" ] || continue
        fi
        printf '%s\0' "$obj"
    done < <(find "$OBJ_DIR" -name '*.o' -type f -print0)
}

OBJ_COUNT=$(list_objects | tr -cd '\0' | wc -c)
if [ "$OBJ_COUNT" -eq 0 ]; then
    echo "module-linkgraph: no .o files under $OBJ_DIR" >&2
    echo "  Run 'make build-only -j\$(nproc)' first." >&2
    exit 1
fi

# --fas is a post-pass over the summary edge list, so the scan itself runs in
# summary mode and the analysis happens below.
AWK_MODE="$MODE"
[ "$MODE" = "fas" ] && AWK_MODE=summary

NM_BIN="${NM:-nm}"
command -v "$NM_BIN" >/dev/null 2>&1 || {
    echo "module-linkgraph: '$NM_BIN' not found on PATH" >&2; exit 1; }

# LTO trap. The production tree compiles with -flto=auto, so its objects are
# SLIM: the real symbol table lives in GCC's private .gnu.lto_* sections and
# the ELF .symtab holds little more than a `__gnu_lto_slim` marker. `nm` reads
# them correctly ONLY by loading the LTO linker plugin. A binutils build
# without that plugin returns a nearly empty symbol table — which would make
# every consumer of this tool report "no cross-module edges" and every gate go
# green on a lie. So: measure, then refuse to emit an empty graph from a
# non-empty object tree. Exit 3 marks exactly that condition.
#
# The in-binary link graph makes the OPPOSITE call, deliberately, and the two
# are not in conflict. cognition/modules/codeindex/src/codeindex_linkdeps.c is a C ELF reader
# with no LTO plugin to load, so it probes for the `__gnu_lto_*` marker and
# SKIPS a slim root entirely rather than parse a compiler-internal format —
# meaning `code linkdeps` reads a test/dev tree while these gates read
# build/obj. That is why the navigator and the gates can legitimately report
# different graphs; neither is stale. Do not "fix" it by making one read the
# other's tree.

# One nm invocation per batch (xargs splits), -A so every line carries its
# object path. Sorted output keeps the report stable across runs.
OUT=$(list_objects \
  | sort -z \
  | xargs -0 "$NM_BIN" -A -g -- 2>/dev/null \
  | awk -v objdir="$OBJ_DIR" -v mode="$AWK_MODE" '
    # Map a repo-relative source path to its navigator group (module).
    function group(p,   n, rest, slash) {
        if (p ~ /^lib\//)      { rest = substr(p, 5); }
        else if (p ~ /^app\//) { rest = substr(p, 5); }
        else if (p ~ /^domain\//) { rest = substr(p, 8); }
        else if (p ~ /^core\//)     { return "core"; }
        else if (p ~ /^config\//)   { return "config"; }
        else if (p ~ /^tools\//)    { return "tools"; }
        else if (p ~ /^adapters\//) { return "adapters"; }
        else if (p ~ /^ports\//)    { return "ports"; }
        else { return "root"; }
        slash = index(rest, "/");
        if (slash == 0) return "root";
        n = substr(rest, 1, slash - 1);
        if (p ~ /^lib\//) return "lib/" n;
        if (p ~ /^app\//) return "app/" n;
        return "domain/" n;
    }
    BEGIN { FS = ":"; olen = length(objdir) + 2 }
    {
        # "<objpath>:<addr-or-blanks> <type> <symbol>"
        colon = index($0, ":");
        obj = substr($0, 1, colon - 1);
        body = substr($0, colon + 1);
        nf = split(body, f, /[ \t]+/);
        # f[] may lead with an empty field when the address column is blank.
        i = 1; while (i <= nf && f[i] == "") i++;
        if (i > nf) next;
        # Defined lines have addr then type then name; undefined lines have
        # only type then name.
        if (i + 2 <= nf)      { type = f[i + 1]; sym = f[i + 2] }
        else if (i + 1 <= nf) { type = f[i];     sym = f[i + 1] }
        else next;
        if (sym == "") next;

        src = substr(obj, olen);        # strip "<objdir>/"
        sub(/\.o$/, ".c", src);
        g = group(src);
        seen_module[g] = 1;

        if (type == "U" || type == "w") {
            # Keyed by (module, symbol, file) so --edges keeps every
            # reference SITE; --summary dedupes back down to symbols.
            ref_seen[g SUBSEP sym SUBSEP src] = 1;
        } else {
            # First definer wins; a symbol defined in several modules is
            # ambiguous and is reported (and skipped) below.
            if (sym in owner) {
                if (owner[sym] != g) ambiguous[sym] = 1;
            } else {
                owner[sym] = g;
            }
        }
    }
    END {
        if (mode == "modules") {
            for (m in seen_module) print m;
            exit 0
        }
        for (key in ref_seen) {
            split(key, parts, SUBSEP);
            from = parts[1]; sym = parts[2]; src = parts[3];
            if (!(sym in owner)) continue;      # libc / vendor / genuinely external
            if (sym in ambiguous) continue;     # multiply defined: not a clean edge
            to = owner[sym];
            if (to == from) continue;           # intra-module
            if (mode == "edges") {
                printf "%s\t%s\t%s\t%s\n", from, to, sym, src;
            } else {
                ekey = from SUBSEP to;
                if ((ekey SUBSEP sym) in sym_seen) continue;
                sym_seen[ekey SUBSEP sym] = 1;
                cnt[ekey]++;
                syms[ekey] = (ekey in syms) ? syms[ekey] "," sym : sym;
            }
        }
        if (mode == "summary") {
            for (ekey in cnt) {
                split(ekey, parts, SUBSEP);
                printf "%s -> %s\t%d\t%s\n", parts[1], parts[2], cnt[ekey], syms[ekey];
            }
        }
    }
' | sort)

if [ -z "$OUT" ]; then
    if [ "$MODE" = "modules" ]; then
        echo "module-linkgraph: no modules resolved from $OBJ_DIR" >&2
        exit 3
    fi
    echo "module-linkgraph: $OBJ_COUNT object(s) under $OBJ_DIR produced ZERO" >&2
    echo "  cross-module edges. That is not a clean tree — it means the symbol" >&2
    echo "  tables could not be read. Almost always: these are slim -flto=auto" >&2
    echo "  objects and '$NM_BIN' has no LTO plugin. Point the tool at a" >&2
    echo "  non-LTO tree instead:" >&2
    echo "    tools/dev/module-linkgraph.sh --obj-dir build/test-rel-obj/epochs/<epoch>" >&2
    echo "  or install a binutils with the GCC LTO plugin." >&2
    exit 3
fi

if [ "$MODE" != "fas" ]; then
    printf '%s\n' "$OUT"
    exit 0
fi

# ── --fas: cycle structure of the lib/ subgraph ─────────────────────────────
# Two questions, both answered exactly:
#
#   1. Which modules are mutually reachable? (Tarjan strongly-connected
#      components.) A component of size 1 can always be ranked; a component of
#      size >1 cannot be ordered without some edge running backward.
#
#   2. How few edges MUST run backward? That is the minimum feedback arc set,
#      and it decomposes over components — an edge between two different
#      components can always be made forward by ordering the components
#      topologically — so the graph-wide minimum is the sum of the per-component
#      minima, and each component can be solved on its own.
#
# Within a component we solve it exactly by dynamic programming over subsets
# rather than by enumerating orderings: dp[S] is the cheapest way to occupy the
# |S| lowest ranks with exactly the modules in S, and appending module v costs
# one for every edge from v to a module not yet placed (those necessarily point
# upward). That is O(2^n * n) instead of O(n!), so a component growing from 7 to
# 12 members stays instant where permutation enumeration would not.
printf '%s\n' "$OUT" \
  | awk -F'\t' '$1 ~ /^lib\/.* -> lib\//' \
  | grep -v 'lib/test' \
  | awk -F'\t' '{ split($1, a, " -> "); print a[1], a[2] }' \
  | awk '
    { u = $1; v = $2
      if (!(u in id)) { id[u] = n; name[n] = u; n++ }
      if (!(v in id)) { id[v] = n; name[n] = v; n++ }
      eu[m] = id[u]; ev[m] = id[v]; m++
      adj[id[u]] = (id[u] in adj) ? adj[id[u]] " " id[v] : "" id[v]
    }

    # ---- Tarjan, iterative (awk has no deep-recursion guarantee) ----
    function scc(   v, w, i, k, sp, top, ai, na, arr) {
        cnt = 0; nc = 0; sp = 0; top = 0
        for (v = 0; v < n; v++) idx[v] = -1
        for (v = 0; v < n; v++) {
            if (idx[v] != -1) continue
            top = 0; cs[top] = v; ce[top] = 0; top++
            while (top > 0) {
                k = top - 1; w = cs[k]
                if (ce[k] == 0) { idx[w] = low[w] = ++cnt; stk[sp++] = w; onstk[w] = 1 }
                na = split((w in adj) ? adj[w] : "", arr, " ")
                if (ce[k] < na) {
                    ai = arr[++ce[k]]
                    if (idx[ai] == -1) { cs[top] = ai; ce[top] = 0; top++ }
                    else if (onstk[ai] && idx[ai] < low[w]) low[w] = idx[ai]
                    continue
                }
                top--
                if (top > 0) { i = cs[top - 1]; if (low[w] < low[i]) low[i] = low[w] }
                if (low[w] == idx[w]) {
                    do { i = stk[--sp]; onstk[i] = 0; comp[i] = nc } while (i != w)
                    nc++
                }
            }
        }
    }

    # ---- exact minimum feedback arc set of one component, by subset DP ----
    function mfas(c,   mem, sz, i, j, e, full, S, v, bit, add, best, bs, bv, order, out, t) {
        sz = 0
        for (i = 0; i < n; i++) if (comp[i] == c) { mem[sz] = i; loc[i] = sz; sz++ }
        if (sz < 2) return -1
        ne2 = 0
        for (e = 0; e < m; e++)
            if (comp[eu[e]] == c && comp[ev[e]] == c) { su[ne2] = loc[eu[e]]; sv[ne2] = loc[ev[e]]; ne2++ }
        printf "\ncomponent (%d modules, %d internal edges):\n  ", sz, ne2
        for (i = 0; i < sz; i++) printf "%s ", name[mem[i]]
        printf "\n"
        if (sz > 20) { printf "  component too large for exact solution (%d modules)\n", sz; return -1 }
        full = 2 ^ sz
        for (S = 0; S < full; S++) dp[S] = -1
        dp[0] = 0
        for (S = 0; S < full; S++) {
            if (dp[S] < 0) continue
            for (v = 0; v < sz; v++) {
                bit = int(S / (2 ^ v)) % 2
                if (bit) continue
                add = 0
                for (e = 0; e < ne2; e++) {
                    if (su[e] != v) continue
                    j = sv[e]
                    if (j == v) continue
                    if (int(S / (2 ^ j)) % 2 == 0) add++      # target not yet placed => upward
                }
                t = S + 2 ^ v
                if (dp[t] < 0 || dp[S] + add < dp[t]) { dp[t] = dp[S] + add; par[t] = v }
            }
        }
        best = dp[full - 1]
        printf "  exact minimum feedback arc set = %d\n", best
        # Walk the choice back out to name the edges a best ranking leaves.
        S = full - 1; j = sz
        while (S > 0) { v = par[S]; order[--j] = v; S = S - 2 ^ v }
        for (i = 0; i < sz; i++) pos[order[i]] = i
        printf "  a ranking that achieves it (lowest rank first):\n    "
        for (i = 0; i < sz; i++) printf "%s ", name[mem[order[i]]]
        printf "\n  the %d edge(s) it leaves running backward:\n", best
        for (e = 0; e < ne2; e++)
            if (pos[sv[e]] > pos[su[e]])
                printf "    %s -> %s\n", name[mem[su[e]]], name[mem[sv[e]]]
        return best
    }

    END {
        if (n == 0) { print "no lib/ -> lib/ edges measured"; exit 1 }
        scc()
        ntriv = 0
        for (c = 0; c < nc; c++) { k = 0; for (i = 0; i < n; i++) if (comp[i] == c) k++; if (k > 1) ntriv++ }
        printf "lib/ subgraph: %d modules, %d edges, %d strongly-connected component(s), %d non-trivial\n",
               n, m, nc, ntriv
        total = 0
        for (c = 0; c < nc; c++) { r = mfas(c); if (r > 0) total += r }
        printf "\nMINIMUM FEEDBACK ARC SET over the whole lib/ subgraph = %d\n", total
        printf "That is the floor on how many entries tools/scripts/lib_module_order_baseline.txt\n"
        printf "can hold: no reordering of engine/composition/lib_module_order.def gets below it. Paying one\n"
        printf "down means breaking a cycle, not re-ranking.\n"
    }
'
