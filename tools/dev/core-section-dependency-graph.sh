#!/bin/sh
# core-section-dependency-graph.sh — MEASURE the directed dependency graph
# AMONG the sealed core's subsystems.
#
# WHY: the sealed core (core/MANIFEST.sha3) is one atomic unit — a single ROOT
# over every sealed file — so nothing under it can be versioned, swapped, or
# re-sealed on its own. The product direction is to make a SECTION the swap
# unit, with bounded explicit interfaces, so a module's reach is bounded BY
# CONSTRUCTION instead of measured after the fact. That is only possible if the
# subsystems are actually separable. This tool produces the evidence for that
# decision. It CHANGES NOTHING: it does not touch the seal, the manifest, the
# pin header, admission, or any module. Read-only measurement.
#
# WHAT A "SUBSYSTEM" IS, derived not named: the manifest's SECTION rows are
# Merkle DIRECTORY nodes and include every ancestor (core, core/chainparams,
# core/chainparams/include, ...). This tool keeps only the sections that own a
# source layout of their own — a SECTION directory that has a SECTION child
# ending in /include or /src. On today's manifest that rule yields exactly
# core/chainparams, core/consensus, core/math, core/params, lib/validation.
# The rule is mechanical; if the manifest gains a subsystem the tool finds it.
#
# THREE INDEPENDENT AXES, all measured, none inferred from a name:
#
#   INCLUDE-CLOSURE   Per sealed file, the compiler's own transitive include
#                     answer (`cc -MM` with the flags make itself reports for
#                     CACHED_CFLAGS), filtered to sealed files. This is the
#                     true reseal blast radius: if B is anywhere in A's closure,
#                     editing B recompiles A. Conditional compilation is honored
#                     because the preprocessor, not a regex, decided it.
#
#   INCLUDE-DIRECT    The `#include` lines of the file itself, each resolved
#                     against the same -I search path (and, for a quoted form,
#                     the including file's own directory). This is the subset a
#                     refactor must actually CUT to break an edge; the closure
#                     axis alone cannot tell a first-hand dependency from one
#                     inherited three headers deep. Every direct resolution is
#                     cross-checked for membership in that file's -MM closure,
#                     and any that is missing is reported under UNDETERMINED
#                     rather than silently trusted.
#
#   SYMBOL            Each sealed .c compiled to a real ELF object and read with
#                     `nm -P`: uppercase codes are DEFINES, `U` are references.
#                     A reference resolved in another subsystem's defines is a
#                     link-time edge. This catches dependencies that no header
#                     reveals — a symbol declared in a third module's header, or
#                     declared locally at the use site.
#
# The reported adjacency matrix is the UNION of the three. Direction is
# meaningful: a cell A -> B means A depends on B.
#
# LIMITS, stated so nobody over-reads a clean graph as a safety guarantee:
#
#   * FUNCTION-POINTER DISPATCH IS INVISIBLE. This codebase dispatches through
#     handler tables and callbacks. If subsystem A stores a pointer into a table
#     that subsystem B later calls, no `#include` and no undefined symbol in B
#     records it. No static tool resolves that, this one included. A missing
#     edge here is NOT proof that no dependency exists.
#   * SEMANTIC AND ORDERING COUPLING IS INVISIBLE. Two subsystems that must
#     agree on a consensus rule, an activation height, or a serialization order
#     but share no header and no symbol show as unconnected. They are not.
#   * THE SYMBOL AXIS IS PER-OBJECT, NOT WHOLE-PROGRAM. It records who
#     references whom directly. A calls a non-sealed helper that calls B shows
#     nothing, exactly as tools/dev/hotswap-core-section-reach.sh states for its
#     own axes. Transitive semantic dependence is not measured here either.
#   * OBJECTS ARE BUILT WITH LTO DISABLED so `nm` sees a real symbol table
#     instead of a GIMPLE stub. Extern linkage is unchanged by that, but the
#     objects are measurement artifacts under the work directory and are never
#     the objects the node links.
#   * SEALED HEADERS ARE MEASURED, NOT SEALED HEADERS' USERS. Scope is the
#     sealed set only. Which non-sealed code depends on these subsystems is a
#     different question and this tool does not answer it.
#
# Usage: tools/dev/core-section-dependency-graph.sh [--cflags=STR] [--work=DIR]
#        --cflags=STR  use STR instead of asking make for CACHED_CFLAGS
#        --work=DIR    keep artifacts in DIR instead of a temp dir (not removed)
set -eu

REPO=$(cd -- "$(dirname -- "$0")/../.." && pwd)
cd -- "$REPO"

MANIFEST=core/MANIFEST.sha3

CFLAGS_IN=""
WORK=""
for a in "$@"; do
  case "$a" in
    --cflags=*) CFLAGS_IN=${a#--cflags=} ;;
    --work=*)   WORK=${a#--work=} ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

KEEP=1
if [ -z "$WORK" ]; then
  mkdir -p "${TMPDIR:-$REPO/build/tmp}"
  WORK=$(mktemp -d "${TMPDIR:-$REPO/build/tmp}/csdg.XXXXXX")
  KEEP=0
fi
mkdir -p "$WORK"
[ "$KEEP" = 1 ] || trap 'rm -rf -- "$WORK"' EXIT HUP INT TERM

[ -f "$MANIFEST" ] || { echo "no sealed manifest at $MANIFEST" >&2; exit 2; }

# ---- INPUTS (print them, so the result is reproducible not asserted) ------
echo "# core-section-dependency-graph — INPUTS"
printf '#   repo               %s\n' "$REPO"
printf '#   git HEAD           %s\n' "$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo '<not a git repo>')"
printf '#   git dirty files    %s\n' "$(git -C "$REPO" status --porcelain 2>/dev/null | wc -l)"
printf '#   manifest           %s (%s bytes)\n' "$MANIFEST" "$(wc -c < "$MANIFEST")"
printf '#   sealed ROOT        %s\n' "$(awk '$1=="ROOT"{print $2}' "$MANIFEST")"
printf '#   sealed TREE        %s\n' "$(awk '$1=="TREE"{print $2}' "$MANIFEST")"
printf '#   compiler           %s\n' "$(${CC:-cc} --version 2>/dev/null | head -1)"
printf '#   nm                 %s\n' "$(nm --version 2>/dev/null | head -1)"

# ---- flags: ask make, do not restate the build ---------------------------
# CACHED_CFLAGS is the build's own compile flag set with the build-identity
# defines already filtered out, so the same tree yields the same string.
if [ -z "$CFLAGS_IN" ]; then
  printf 'include Makefile\nzcl-print-var:\n\t@printf %%s\\\\n "$(%s)"\n' '$(ZCL_V)' \
    > "$WORK/print.mk"
  if nice -n 10 make -f "$WORK/print.mk" ZCL_V=CACHED_CFLAGS zcl-print-var \
       > "$WORK/flags.raw" 2>"$WORK/flags.err"; then
    CFLAGS_IN=$(tail -1 "$WORK/flags.raw")
  fi
  [ -n "$CFLAGS_IN" ] || {
    echo "could not obtain CACHED_CFLAGS from make; pass --cflags=" >&2
    tail -3 "$WORK/flags.err" >&2 || true
    exit 2
  }
  printf '#   flag source        make CACHED_CFLAGS (%s bytes)\n' "${#CFLAGS_IN}"
else
  printf '#   flag source        --cflags= override (%s bytes)\n' "${#CFLAGS_IN}"
fi
# LTO off for the SYMBOL axis only, so nm sees a real symbol table; see LIMITS.
# -Wno-error with it: dropping LTO changes inlining, and one sealed TU then
# trips a -Warray-bounds false positive the real (LTO) build does not. Symbol
# tables do not depend on warnings, so demoting them changes no measurement.
CFLAGS_OBJ="$(printf '%s' "$CFLAGS_IN" | sed 's/-flto=[^ ]*//g; s/ -flto / /g') -Wno-error"

# ---- sealed set + subsystem derivation -----------------------------------
awk '$1 ~ /^[0-9a-f]{64}$/ {print $2}' "$MANIFEST" | sort > "$WORK/sealed"
awk '$1=="SECTION"{print $5}' "$MANIFEST" | sort > "$WORK/sections"
# subsystem := a SECTION with a SECTION child named .../include or .../src
: > "$WORK/subsys"
while IFS= read -r d; do
  if grep -aqx -e "$d/include" -e "$d/src" "$WORK/sections"; then
    printf '%s\n' "$d" >> "$WORK/subsys"
  fi
done < "$WORK/sections"
sort -u "$WORK/subsys" -o "$WORK/subsys"
NSUB=$(wc -l < "$WORK/subsys")
NSEALED=$(wc -l < "$WORK/sealed")
printf '#   sealed files       %s\n' "$NSEALED"
printf '#   sealed sections    %s\n' "$(wc -l < "$WORK/sections")"
printf '#   subsystems         %s (%s)\n' "$NSUB" "$(tr '\n' ' ' < "$WORK/subsys")"
echo "#"

# file -> subsystem (longest matching subsystem prefix; a sealed file under no
# subsystem, e.g. core/UNSEAL.md, is reported and excluded from the graph)
: > "$WORK/fsub"
: > "$WORK/orphan"
while IFS= read -r f; do
  s=$(awk -v f="$f" '{ if (index(f, $0 "/")==1 && length($0)>length(b)) b=$0 } END{print b}' "$WORK/subsys")
  if [ -n "$s" ]; then printf '%s\t%s\n' "$f" "$s" >> "$WORK/fsub"
  else printf '%s\n' "$f" >> "$WORK/orphan"; fi
done < "$WORK/sealed"

# ---- -I search path, in the order the compiler uses it -------------------
printf '%s\n' "$CFLAGS_IN" | tr ' ' '\n' | sed -n 's/^-I//p' | awk 'NF' > "$WORK/ipath"

# ---- AXIS 1 + 2: include closure and direct includes ---------------------
: > "$WORK/e_closure"   # from_file \t to_file
: > "$WORK/e_direct"    # from_file \t to_file
: > "$WORK/gaps"

while IFS= read -r f; do
  case "$f" in *.c|*.h|*.inc) ;; *) continue ;; esac
  # closure: compile the file as a TU. Headers and .inc need -x c.
  case "$f" in
    *.c) XF="" ;;
    *)   XF="-x c" ;;
  esac
  # shellcheck disable=SC2086
  if nice -n 10 ${CC:-cc} $CFLAGS_IN $XF -MM -MF "$WORK/dep" "$f" 2>"$WORK/cerr"; then
    tr ' \\' '\n\n' < "$WORK/dep" | awk 'NF && !/:$/' | sed 's/^\.\///' | sort -u \
      > "$WORK/clo"
    awk -v f="$f" 'NR==FNR{s[$0]=1;next} ($0 in s) && $0!=f {print f"\t"$0}' \
      "$WORK/sealed" "$WORK/clo" >> "$WORK/e_closure"
  else
    printf 'CLOSURE\t%s\tpreprocess failed: %s\n' "$f" "$(head -1 "$WORK/cerr")" \
      >> "$WORK/gaps"
    : > "$WORK/clo"
  fi
  # direct: resolve this file's own #include lines against the same search path
  d=$(dirname -- "$f")
  LC_ALL=C grep -aoE '^[[:space:]]*#[[:space:]]*include[[:space:]]*[<"][^">]+[">]' "$f" 2>/dev/null \
    | sed -E 's/.*[<"]([^">]+)[">].*/\1/' | sort -u > "$WORK/inc" || true
  while IFS= read -r h; do
    [ -n "$h" ] || continue
    r=""
    [ -f "$d/$h" ] && r="$d/$h"
    if [ -z "$r" ]; then
      while IFS= read -r p; do
        if [ -f "$p/$h" ]; then r="$p/$h"; break; fi
      done < "$WORK/ipath"
    fi
    [ -n "$r" ] || continue
    r=$(printf '%s' "$r" | sed 's|//*|/|g; s|^\./||')
    grep -aqx "$r" "$WORK/sealed" || continue
    [ "$r" != "$f" ] || continue
    printf '%s\t%s\n' "$f" "$r" >> "$WORK/e_direct"
    # cross-check: a direct sealed include must appear in the -MM closure
    grep -aqx "$r" "$WORK/clo" || \
      printf 'DIRECT-NOT-IN-CLOSURE\t%s\t%s (conditional compilation, or -I order differs)\n' \
        "$f" "$r" >> "$WORK/gaps"
  done < "$WORK/inc"
done < "$WORK/sealed"
sort -u "$WORK/e_closure" -o "$WORK/e_closure"
sort -u "$WORK/e_direct"  -o "$WORK/e_direct"

# ---- AXIS 3: symbols -----------------------------------------------------
mkdir -p "$WORK/obj"
NPAR=4; n=0
grep -a '\.c$' "$WORK/sealed" > "$WORK/csrc" || true
while IFS= read -r f; do
  o="$WORK/obj/$(printf '%s' "$f" | tr / _).o"
  # shellcheck disable=SC2086
  ( nice -n 10 ${CC:-cc} $CFLAGS_OBJ -c "$f" -o "$o" 2>"$o.err" || : ) &
  n=$((n+1)); [ "$n" -lt "$NPAR" ] || { wait; n=0; }
done < "$WORK/csrc"
wait

: > "$WORK/defs"   # symbol \t subsystem \t file
: > "$WORK/refs"   # symbol \t subsystem \t file
while IFS= read -r f; do
  s=$(awk -F'\t' -v f="$f" '$1==f{print $2}' "$WORK/fsub")
  o="$WORK/obj/$(printf '%s' "$f" | tr / _).o"
  if [ ! -f "$o" ]; then
    printf 'SYMBOL\t%s\tcompile failed: %s\n' "$f" \
      "$(head -1 "$o.err" 2>/dev/null)" >> "$WORK/gaps"
    continue
  fi
  nm -P "$o" 2>/dev/null | awk -v s="$s" -v f="$f" '
    NF>=2 && $1 !~ /^\./ {
      c=$2
      if (c=="U")                       print "R\t"$1"\t"s"\t"f
      else if (c ~ /^[A-TV-Z]$/)        print "D\t"$1"\t"s"\t"f
    }' >> "$WORK/nmraw"
done < "$WORK/csrc"
awk -F'\t' '$1=="D"{print $2"\t"$3"\t"$4}' "$WORK/nmraw" | sort -u > "$WORK/defs"
awk -F'\t' '$1=="R"{print $2"\t"$3"\t"$4}' "$WORK/nmraw" | sort -u > "$WORK/refs"
# a reference resolved in ANOTHER subsystem's defines is an edge
awk -F'\t' 'NR==FNR{d[$1]=d[$1]" "$2; dn[$1]=$3; next}
  { if ($1 in d) { n=split(d[$1],a," "); for(i=1;i<=n;i++) if(a[i]!=$2)
      print $2"\t"a[i]"\t"$1"\t"$3"\t"dn[$1] } }' \
  "$WORK/defs" "$WORK/refs" | sort -u > "$WORK/e_symbol"   # fromsub tosub sym fromfile tofile

printf '#   sealed .c objects  %s of %s compiled\n' \
  "$(find "$WORK/obj" -name '*.o' | wc -l)" "$(wc -l < "$WORK/csrc")"
printf '#   extern defines     %s   references resolved cross-subsystem: %s\n#\n' \
  "$(wc -l < "$WORK/defs")" "$(wc -l < "$WORK/e_symbol")"

# ---- edge tables ---------------------------------------------------------
# subsystem-level edges per axis
awk -F'\t' 'NR==FNR{m[$1]=$2;next} {a=m[$1];b=m[$2]; if(a!=""&&b!=""&&a!=b) print a"\t"b}' \
  "$WORK/fsub" "$WORK/e_closure" | sort > "$WORK/s_closure"
awk -F'\t' 'NR==FNR{m[$1]=$2;next} {a=m[$1];b=m[$2]; if(a!=""&&b!=""&&a!=b) print a"\t"b}' \
  "$WORK/fsub" "$WORK/e_direct" | sort > "$WORK/s_direct"
cut -f1,2 "$WORK/e_symbol" | sort > "$WORK/s_symbol"
cat "$WORK/s_closure" "$WORK/s_direct" "$WORK/s_symbol" | sort -u > "$WORK/s_union"
# FIRST-HAND graph: only edges a file makes for itself — its own #include line
# or its own undefined symbol. The union graph additionally carries edges
# INHERITED through a third subsystem's header; those are real reseal coupling
# but they are not something either endpoint can be edited to remove, so the
# refactoring question is asked of this graph, not the union.
cat "$WORK/s_direct" "$WORK/s_symbol" | sort -u > "$WORK/s_first"

short() { printf '%s' "${1##*/}"; }
has_edge() { awk -F'\t' -v a="$2" -v b="$3" '$1==a&&$2==b{f=1} END{exit !f}' "$1"; }

# ---- MATRIX --------------------------------------------------------------
matrix() {  # $1=title $2=graph-file $3=1 to annotate axis letters
  echo "$1"
  echo
  printf '%-20s' "DEPENDS ON ->"
  while IFS= read -r c; do printf '%-14s' "$(short "$c")"; done < "$WORK/subsys"
  echo
  while IFS= read -r r; do
    printf '%-20s' "$(short "$r")"
    while IFS= read -r c; do
      if [ "$r" = "$c" ]; then printf '%-14s' "-"; continue; fi
      cell="."
      if has_edge "$2" "$r" "$c"; then
        if [ "$3" = 1 ]; then
          cell=""
          has_edge "$WORK/s_direct" "$r" "$c" && cell="${cell}D"
          has_edge "$WORK/s_symbol" "$r" "$c" && cell="${cell}S"
          if [ -z "$cell" ]; then cell="(c)"; else
            has_edge "$WORK/s_closure" "$r" "$c" && cell="${cell}i"
          fi
        else
          cell="X"
        fi
      fi
      printf '%-14s' "$cell"
    done < "$WORK/subsys"
    echo
  done < "$WORK/subsys"
  echo
}
echo "== MATRIX (UNION of all three axes) — row DEPENDS ON column =="
echo "   D  a first-hand #include of the column's sealed header"
echo "   S  a first-hand undefined symbol the column defines"
echo "   i  additionally present in the -MM include closure"
echo "   (c) CLOSURE-ONLY — inherited through a third subsystem's header;"
echo "       neither endpoint can remove it by editing itself"
echo "   .  no edge measured on any axis        -  self"
matrix "" "$WORK/s_union" 1

# ---- EDGE DETAIL ---------------------------------------------------------
echo "== EDGES — weight and the concrete carriers =="
echo "   inc-direct  distinct (from-file, to-file) pairs with a first-hand #include"
echo "   inc-closure distinct pairs where to-file is anywhere in from-file's -MM closure"
echo "   symbols     distinct symbol names referenced across the boundary"
echo
while IFS= read -r a; do
  while IFS= read -r b; do
    [ "$a" != "$b" ] || continue
    has_edge "$WORK/s_union" "$a" "$b" || continue
    nd=$(awk -F'\t' -v A="$a" -v B="$b" 'NR==FNR{m[$1]=$2;next} m[$1]==A&&m[$2]==B' \
         "$WORK/fsub" "$WORK/e_direct" | wc -l)
    nc=$(awk -F'\t' -v a="$a" -v b="$b" '$1==a&&$2==b' "$WORK/s_closure" | wc -l)
    ns=$(cut -f1,2,3 "$WORK/e_symbol" | sort -u \
         | awk -F'\t' -v a="$a" -v b="$b" '$1==a&&$2==b{print $3}' | sort -u | wc -l)
    printf '%s -> %s' "$a" "$b"
    if [ "$nd" = 0 ] && [ "$ns" = 0 ]; then printf '   [CLOSURE-ONLY]'; fi
    echo
    printf '    inc-direct=%-4s inc-closure=%-4s symbols=%s\n' "$nd" "$nc" "$ns"
    awk -F'\t' -v A="$a" -v B="$b" 'NR==FNR{m[$1]=$2;next} m[$1]==A&&m[$2]==B{print $2}' \
      "$WORK/fsub" "$WORK/e_direct" | sort | uniq -c | sort -k1,1nr -k2,2 | head -3 \
      | while read -r n hdr; do printf '      header  %-52s (%s direct includers)\n' "$hdr" "$n"; done
    awk -F'\t' -v a="$a" -v b="$b" '$1==a&&$2==b{print $3"\t"$5}' "$WORK/e_symbol" \
      | sort -u | head -3 \
      | while IFS='	' read -r sym def; do printf '      symbol  %-52s defined in %s\n' "$sym" "$def"; done
    if [ "$nd" = 0 ] && [ "$ns" = 0 ]; then
      awk -F'\t' -v A="$a" -v B="$b" 'NR==FNR{m[$1]=$2;next} m[$1]==A&&m[$2]==B{print "      inherited via  "$1" -> "$2}' \
        "$WORK/fsub" "$WORK/e_closure" | sort -u | head -3
    fi
    echo
  done < "$WORK/subsys"
done < "$WORK/subsys"

# ---- FIRST-HAND VIEW -----------------------------------------------------
matrix "== MATRIX (FIRST-HAND only: own #include or own symbol) ==   X = edge" \
  "$WORK/s_first" 0

# ---- LEAVES + CYCLES -----------------------------------------------------
report_graph() {  # $1=label $2=graph-file
  echo "-- $1"
  any=0
  while IFS= read -r a; do
    if [ "$(awk -F'\t' -v a="$a" '$1==a' "$2" | wc -l)" = 0 ]; then
      printf '   LEAF (depends on no other sealed subsystem): %s\n' "$a"; any=1
    fi
  done < "$WORK/subsys"
  [ "$any" = 1 ] || echo "   no leaf — every subsystem depends on at least one other."
  awk -F'\t' '
    { e[$1 SUBSEP $2]=1; nodes[$1]=1; nodes[$2]=1 }
    END{
      n=0; for (v in nodes) N[++n]=v
      for (k=1;k<=n;k++) for (i=1;i<=n;i++) for (j=1;j<=n;j++)
        if ((N[i] SUBSEP N[k]) in e && (N[k] SUBSEP N[j]) in e) e[N[i] SUBSEP N[j]]=1
      c=0
      for (i=1;i<=n;i++) if ((N[i] SUBSEP N[i]) in e) { c++; print "   ON A CYCLE: " N[i] }
      if (c==0) print "   NO CYCLE — this graph is a DAG."
    }' "$2" | sort
  awk -F'\t' '{e[$1 SUBSEP $2]=1; nodes[$1]=1; nodes[$2]=1}
    END{
      n=0; for (v in nodes) N[++n]=v
      for (i=1;i<=n;i++) for (j=1;j<=n;j++) if (i<j)
        if ((N[i] SUBSEP N[j]) in e && (N[j] SUBSEP N[i]) in e)
          print "   2-cycle: " N[i] " <-> " N[j]
      for (i=1;i<=n;i++) for (j=1;j<=n;j++) for (k=1;k<=n;k++)
        if (i!=j && j!=k && i!=k && i<j && i<k)
          if ((N[i] SUBSEP N[j]) in e && (N[j] SUBSEP N[k]) in e && (N[k] SUBSEP N[i]) in e)
            print "   3-cycle: " N[i] " -> " N[j] " -> " N[k] " -> " N[i]
    }' "$2" | sort
  echo
}
echo "== LEAVES AND CYCLES =="
echo "   A cycle means those subsystems cannot be versioned independently: they"
echo "   are one swap unit until the cycle is cut. A leaf is the cheapest place"
echo "   to prove the swap mechanism, because nothing sealed constrains it."
echo
report_graph "UNION graph (reseal blast radius)" "$WORK/s_union"
report_graph "FIRST-HAND graph (what a refactor can actually cut)" "$WORK/s_first"

# ---- narrowness ranking --------------------------------------------------
echo "== FIRST-HAND EDGES RANKED BY INTERFACE WIDTH =="
echo "   width = distinct direct-include headers + distinct crossing symbols."
echo "   A narrow edge is a candidate for an explicit versioned interface."
echo
{ while IFS='	' read -r a b; do
    nd=$(awk -F'\t' -v A="$a" -v B="$b" 'NR==FNR{m[$1]=$2;next} m[$1]==A&&m[$2]==B{print $2}' \
         "$WORK/fsub" "$WORK/e_direct" | sort -u | wc -l)
    ns=$(awk -F'\t' -v a="$a" -v b="$b" '$1==a&&$2==b{print $3}' "$WORK/e_symbol" | sort -u | wc -l)
    printf '%s\t%s\t%s\t%s\t%s\n' "$((nd+ns))" "$a" "$b" "$nd" "$ns"
  done < "$WORK/s_first"; } | sort -k1,1n -k2,2 -k3,3 \
  | while IFS='	' read -r w a b nd ns; do
      printf '   width=%-4s %s -> %s   (headers=%s symbols=%s)\n' "$w" "$a" "$b" "$nd" "$ns"
    done
echo

# ---- UNDETERMINED --------------------------------------------------------
echo "== UNDETERMINED =="
if [ -s "$WORK/orphan" ]; then
  echo "   sealed files under no subsystem (excluded from the graph):"
  sed 's/^/      /' "$WORK/orphan"
fi
if [ -s "$WORK/gaps" ]; then sort -u "$WORK/gaps" | sed 's/^/   /'
else echo "   no measurement gap on any axis."; fi
echo "   NOT MEASURABLE BY ANY STATIC AXIS: function-pointer / handler-table"
echo "   dispatch, and semantic agreement on consensus rules. See this file's"
echo "   header. An absent edge above is not proof of independence."
[ "$KEEP" = 0 ] || printf '\n# artifacts kept in %s\n' "$WORK"
