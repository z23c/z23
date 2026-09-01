#!/bin/sh
# hotswap-core-section-reach.sh — MEASURE which sealed-core SECTIONS each
# swappable hot-swap module actually reaches.
#
# WHY: today a module pins the WHOLE sealed ROOT (ZCL_CORE_SEAL_ROOT), so one
# byte anywhere under the sealed set invalidates every packaged module. Letting
# a module pin only the SECTIONS it depends on is a safety trade. This tool
# produces the evidence for that decision. It CHANGES NOTHING: it does not
# touch the seal, the header, admission, or any pin. Read-only measurement.
#
# TWO INDEPENDENT AXES, both measured, never inferred:
#
#   CALL reach   The module .so's UNDEFINED dynamic symbols (readelf --dyn-syms),
#                resolved against a per-object symbol map of the resident node
#                (nm --defined-only --extern-only over one node-obj epoch).
#                A hit means the module CALLS or READS a body defined by a
#                sealed source file. This is the module's literal, mechanically
#                derivable runtime interface to sealed code.
#
#   COMPILE reach  The module TU's preprocessor include closure (cc -MM with the
#                flags the build itself recorded in build/hotswap/fast/*.cmd),
#                filtered to sealed files. A hit means sealed TEXT — a struct
#                layout, an enum, a macro constant, a static inline — was
#                compiled INTO the module. There is no dynamic symbol for this,
#                so CALL reach alone would miss it entirely.
#
# Island modules (engine/composition/hotswap_islands.def) are compiled as a unity TU; the
# COMPILE axis unions the owner TU and every island member, matching the real
# `hotswap-module-so` recipe.
#
# LIMIT, stated so nobody over-reads the output: both axes are DIRECT reach.
# A module that calls a resident non-sealed function which itself calls sealed
# code shows no hit here. Transitive semantic dependence is NOT measured and
# cannot be measured from the artifact.
#
# Usage: tools/dev/hotswap-core-section-reach.sh [--build-id=HEX] [--epoch=DIR]
set -eu

REPO=$(cd -- "$(dirname -- "$0")/../.." && pwd)
cd -- "$REPO"

MANIFEST=core/MANIFEST.sha3
SWAPPABLE=engine/composition/hotswap_swappable.def
ISLANDS=engine/composition/hotswap_islands.def
SO_DIR=build/hotswap
CMD_DIR=build/hotswap/fast
OBJ_ROOT=build/node-obj/epochs

BUILD_ID=""
EPOCH=""
for a in "$@"; do
  case "$a" in
    --build-id=*) BUILD_ID=${a#--build-id=} ;;
    --epoch=*)    EPOCH=${a#--epoch=} ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

mkdir -p "${TMPDIR:-$REPO/build/tmp}"
WORK=$(mktemp -d "${TMPDIR:-$REPO/build/tmp}/hscsr.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT HUP INT TERM

# ---- resolve inputs -------------------------------------------------------
# Module build id: the id with the MOST .so files (a complete generation),
# ties broken by the newest such .so. Deterministic given the tree.
if [ -z "$BUILD_ID" ]; then
  for f in "$SO_DIR"/*.so; do
    b=${f##*/}; id=$(echo "${b##*-}" | sed 's/\.so$//')
    printf '%s\t%s\n' "$id" "$(stat -c %Y "$f")"
  done > "$WORK/idrows"
  # most .so files wins; tie broken by the NEWEST .so carrying that id.
  awk -F'\t' '{n[$1]++; if($2+0>t[$1]) t[$1]=$2+0} END{for(i in n) print n[i]"\t"t[i]"\t"i}' \
    "$WORK/idrows" | sort -k1,1nr -k2,2nr -k3,3 > "$WORK/ids"
  BUILD_ID=$(head -1 "$WORK/ids" | cut -f3)
fi
if [ -z "$EPOCH" ]; then
  # node object epoch: the one with the most objects, ties by name.
  for d in "$OBJ_ROOT"/*/; do
    n=$(find "$d" -name '*.o' | wc -l)
    printf '%s\t%s\n' "$n" "${d%/}"
  done | sort -k1,1nr -k2,2 > "$WORK/eps"
  EPOCH=$(head -1 "$WORK/eps" | cut -f2)
fi

[ -d "$EPOCH" ] || { echo "no node object epoch: $EPOCH" >&2; exit 2; }

# ---- INPUTS (print them, so the result is reproducible not asserted) ------
echo "# hotswap-core-section-reach — INPUTS"
printf '#   repo               %s\n' "$REPO"
printf '#   git HEAD           %s\n' "$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo '<not a git repo>')"
dirty=$(git -C "$REPO" status --porcelain 2>/dev/null | wc -l)
printf '#   git dirty files    %s\n' "$dirty"
printf '#   manifest           %s (%s bytes, mtime %s)\n' "$MANIFEST" \
  "$(wc -c < "$MANIFEST")" "$(date -r "$MANIFEST" '+%Y-%m-%dT%H:%M:%S%z')"
printf '#   sealed ROOT        %s\n' "$(awk '$1=="ROOT"{print $2}' "$MANIFEST")"
printf '#   sealed TREE        %s\n' "$(awk '$1=="TREE"{print $2}' "$MANIFEST")"
printf '#   module build id    %s\n' "$BUILD_ID"
printf '#   module .so count   %s (dir %s)\n' "$(ls "$SO_DIR"/*-"$BUILD_ID".so 2>/dev/null | wc -l)" "$SO_DIR"
printf '#   node obj epoch     %s (%s objects)\n' "$EPOCH" "$(find "$EPOCH" -name '*.o' | wc -l)"
printf '#   compiler           %s\n' "$(${CC:-cc} --version 2>/dev/null | head -1)"
printf '#   readelf            %s\n' "$(readelf --version 2>/dev/null | head -1)"
printf '#   nm                 %s\n' "$(nm --version 2>/dev/null | head -1)"
# CURRENCY: the sealed core must not have moved since these .so were built,
# or the CALL axis would be measuring a stale sealed set. Both the packaged
# module manifests and the compiled pin header carry the ROOT they were built
# against; compare all three and say so out loud.
M_ROOT=$(awk '$1=="ROOT"{print $2}' "$MANIFEST")
H_ROOT=$(sed -n 's/.*"\([0-9a-f]\{64\}\)".*/\1/p' engine/modules/hotswap/include/hotswap/core_seal_root.h | head -1)
P_ROOT=$(cat "$SO_DIR"/*-"$BUILD_ID".so.manifest 2>/dev/null \
  | sed -n 's/^core_seal_root=//p' | sort -u | tr '\n' ' ')
printf '#   header pin ROOT    %s  %s\n' "$H_ROOT" \
  "$([ "$H_ROOT" = "$M_ROOT" ] && echo '(matches manifest)' || echo '(DIFFERS from manifest)')"
printf '#   packaged pin ROOT  %s %s\n' "${P_ROOT:-<no .so.manifest present>}" \
  "$([ "${P_ROOT% }" = "$M_ROOT" ] && echo '(matches manifest — sealed set unmoved since build)' || echo '(not a single matching value — CALL axis may be stale)')"
echo "#"

# ---- sealed file list + section directories ------------------------------
awk '$1 ~ /^[0-9a-f]{64}$/ {print $2}' "$MANIFEST" | sort > "$WORK/sealed_files"
awk '$1=="SECTION"{print $2"\t"$3"\t"$4}' "$MANIFEST" | sort > "$WORK/sections"
NSEC=$(wc -l < "$WORK/sections")
NSEALED=$(wc -l < "$WORK/sealed_files")
printf '#   sealed files       %s\n#   sealed sections    %s\n#\n' "$NSEALED" "$NSEC"

# ---- swappable TU list ---------------------------------------------------
tr '\n' ' ' < "$SWAPPABLE" \
  | grep -oE 'HOTSWAP_SWAPPABLE\("[^"]*"' \
  | sed 's/HOTSWAP_SWAPPABLE("//; s/"$//' | sort > "$WORK/tus"
NTU=$(wc -l < "$WORK/tus")
printf '#   swappable TUs      %s (from %s)\n#\n' "$NTU" "$SWAPPABLE"

# ---- symbol map: every extern symbol defined by the resident node --------
find "$EPOCH" -name '*.o' | sort > "$WORK/objs"
: > "$WORK/symmap"
while IFS= read -r o; do
  rel=${o#"$EPOCH"/}
  src=${rel%.o}.c
  nm --defined-only --extern-only -P "$o" 2>/dev/null \
    | awk -v s="$src" 'NF>=2 {print $1"\t"s}'
done < "$WORK/objs" | sort -u > "$WORK/symmap"

# sealed subset of that map
awk -F'\t' 'NR==FNR{s[$0]=1;next} ($2 in s)' "$WORK/sealed_files" "$WORK/symmap" \
  > "$WORK/sealed_symmap"
printf '#   node extern syms   %s (of which sealed-defined: %s)\n#\n' \
  "$(wc -l < "$WORK/symmap")" "$(wc -l < "$WORK/sealed_symmap")"

# ---- island members ------------------------------------------------------
tr '\n' ' ' < "$ISLANDS" \
  | grep -oE 'HOTSWAP_ISLAND\("[^"]*"[[:space:]]*,[[:space:]]*"[^"]*"\)' \
  | sed 's/HOTSWAP_ISLAND("//; s/",[[:space:]]*"/\t/; s/")$//' \
  | sort > "$WORK/islands" || true

# ---- per-TU measurement --------------------------------------------------
: > "$WORK/call_hits"     # tu \t sealed_file \t symbol
: > "$WORK/compile_hits"  # tu \t sealed_file
: > "$WORK/gaps"          # tu \t reason

while IFS= read -r tu; do
  safe=$(printf '%s' "$tu" | tr -c 'A-Za-z0-9_.-' '_')
  so="$SO_DIR/$safe-$BUILD_ID.so"

  # --- CALL axis -----------------------------------------------------------
  if [ -f "$so" ]; then
    readelf --dyn-syms -W "$so" 2>/dev/null \
      | awk '$7=="UND" && $8!="" {s=$8; sub(/@.*/,"",s); if(s!="") print s}' \
      | sort -u > "$WORK/und"
    awk -F'\t' -v tu="$tu" 'NR==FNR{u[$0]=1;next} ($1 in u){print tu"\t"$2"\t"$1}' \
      "$WORK/und" "$WORK/sealed_symmap" | sort -u >> "$WORK/call_hits"
    # unresolved undefined symbols that are NOT in the node map and not libc:
    awk -F'\t' 'NR==FNR{m[$1]=1;next} !($0 in m)' "$WORK/symmap" "$WORK/und" \
      > "$WORK/unres"
    printf '%s\t%s\t%s\t%s\n' "$tu" "$(wc -l < "$WORK/und")" \
      "$(wc -l < "$WORK/unres")" "so" >> "$WORK/callstat"
  else
    printf '%s\tno module .so at build id %s (expected %s)\n' "$tu" "$BUILD_ID" "$so" >> "$WORK/gaps"
  fi

  # --- COMPILE axis --------------------------------------------------------
  cmdf="$CMD_DIR/${tu##*/}.cmd"
  cmdf="$CMD_DIR/$safe.cmd"
  if [ -f "$cmdf" ]; then
    flags=$(sed 's|^[^ ]*zcc cc ||; s|^[^ ]*cc ||' "$cmdf")
    members=$(awk -F'\t' -v o="$tu" '$1==o{print $2}' "$WORK/islands")
    : > "$WORK/closure"
    for src in $members $tu; do
      [ -f "$src" ] || continue
      # shellcheck disable=SC2086
      if ${CC:-cc} $flags -fPIC -DZCL_HOTSWAP_MODULE_GEN \
           -DZCL_HOTSWAP_MODULE_SOURCE_TU="\"$tu\"" \
           -MM -MF "$WORK/dep" "$src" 2>"$WORK/cerr"; then
        tr ' \\' '\n\n' < "$WORK/dep" >> "$WORK/closure"
      else
        printf '%s\tpreprocess failed for %s: %s\n' "$tu" "$src" \
          "$(head -1 "$WORK/cerr")" >> "$WORK/gaps"
      fi
    done
    sort -u "$WORK/closure" | awk 'NF' > "$WORK/closure.u"
    awk -F'\t' -v tu="$tu" 'NR==FNR{s[$0]=1;next} ($0 in s){print tu"\t"$0}' \
      "$WORK/sealed_files" "$WORK/closure.u" | sort -u >> "$WORK/compile_hits"
  else
    printf '%s\tno recorded compile command (expected %s)\n' "$tu" "$cmdf" >> "$WORK/gaps"
  fi
done < "$WORK/tus"

# ---- section attribution --------------------------------------------------
# A sealed file belongs to every SECTION directory that is an ancestor, because
# SECTION counts are RECURSIVE: changing one file changes that directory's node
# digest and every ancestor's.
sec_of() {  # $1 = sealed file path -> newline list of section dirs
  f=$1
  while IFS= read -r line; do
    d=$(printf '%s' "$line" | cut -f1)
    case "$f" in "$d"/*) printf '%s\n' "$d" ;; esac
  done < "$WORK/sections"
}

: > "$WORK/tu_sec"   # tu \t section \t axis \t evidence
while IFS='	' read -r tu file sym; do
  sec_of "$file" | while IFS= read -r s; do
    printf '%s\t%s\tCALL\t%s:%s\n' "$tu" "$s" "$sym" "$file" >> "$WORK/tu_sec"
  done
done < "$WORK/call_hits"
while IFS='	' read -r tu file; do
  sec_of "$file" | while IFS= read -r s; do
    printf '%s\t%s\tCOMPILE\t%s\n' "$tu" "$s" "$file" >> "$WORK/tu_sec"
  done
done < "$WORK/compile_hits"
sort -u "$WORK/tu_sec" -o "$WORK/tu_sec"

# ---- TABLE A: per module --------------------------------------------------
echo "== TABLE A — per swappable module: sealed sections reached =="
echo "   (call=N distinct symbols imported from that section's files;"
echo "    compile=N sealed files from that section in the include closure)"
echo
while IFS= read -r tu; do
  printf '%s\n' "$tu"
  awk -F'\t' -v tu="$tu" '$1==tu{key=$2"\t"$3; c[key]++} END{
     for (k in c) print k"\t"c[k] }' "$WORK/tu_sec" | sort > "$WORK/a"
  if [ ! -s "$WORK/a" ]; then
    echo "    <no sealed section reached>"
  else
    cut -f1 "$WORK/a" | sort -u | while IFS= read -r s; do
      call=$(awk -F'\t' -v s="$s" '$1==s && $2=="CALL"{print $3}' "$WORK/a"); call=${call:-0}
      comp=$(awk -F'\t' -v s="$s" '$1==s && $2=="COMPILE"{print $3}' "$WORK/a"); comp=${comp:-0}
      printf '    %-42s call=%-3s compile=%s\n' "$s" "$call" "$comp"
    done
  fi
done < "$WORK/tus"
echo

# ---- TABLE B: per section -------------------------------------------------
echo "== TABLE B — per sealed section: which modules reach it =="
echo
while IFS='	' read -r dir files hex; do
  n=$(awk -F'\t' -v s="$dir" '$2==s{print $1}' "$WORK/tu_sec" | sort -u | wc -l)
  nc=$(awk -F'\t' -v s="$dir" '$2==s && $3=="CALL"{print $1}' "$WORK/tu_sec" | sort -u | wc -l)
  printf '%-42s files=%-4s modules=%s/%s (of which by CALL: %s)\n' "$dir" "$files" "$n" "$NTU" "$nc"
  awk -F'\t' -v s="$dir" '$2==s{print "      "$1}' "$WORK/tu_sec" | sort -u
done < "$WORK/sections"
echo

# ---- TABLE C: the decision number ----------------------------------------
echo "== TABLE C — if ONE section changed, how many of the $NTU modules stay valid? =="
echo "   today (whole-ROOT pin): 0 survive, for a change in ANY section."
echo
printf '%-42s %-9s %-9s\n' "SECTION" "INVALID" "SURVIVE"
while IFS='	' read -r dir files hex; do
  n=$(awk -F'\t' -v s="$dir" '$2==s{print $1}' "$WORK/tu_sec" | sort -u | wc -l)
  printf '%-42s %-9s %-9s\n' "$dir" "$n" "$((NTU - n))"
done < "$WORK/sections"
echo

# ---- gaps -----------------------------------------------------------------
echo "== UNDETERMINED =="
if [ -s "$WORK/gaps" ]; then cat "$WORK/gaps"; else echo "none — all $NTU modules measured on both axes."; fi

# ---- TABLE D: the ceiling — per sealed FILE ------------------------------
echo
echo "== TABLE D — ceiling: if ONE sealed FILE changed, how many modules stay valid? =="
echo "   This is the BEST any granularity could do; section pinning cannot beat it."
echo
cat "$WORK/call_hits" "$WORK/compile_hits" | cut -f1,2 | sort -u > "$WORK/file_hits"
printf '%-56s %-9s %-9s\n' "SEALED FILE" "INVALID" "SURVIVE"
while IFS= read -r f; do
  n=$(awk -F'\t' -v f="$f" '$2==f{print $1}' "$WORK/file_hits" | sort -u | wc -l)
  printf '%-56s %-9s %-9s\n' "$f" "$n" "$((NTU - n))"
done < "$WORK/sealed_files"
