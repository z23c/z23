#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Regenerates slhdsa_vectors.h from the NIST ACVP-Server JSON. Usage:
#   gen_vectors.sh DIR > slhdsa_vectors.h
# where DIR holds keyGen.json, sigGen.json and sigVer.json (the three
# internalProjection.json files named in the header). Needs only jq, awk, sed.
set -eu
dir=$1
commit=975de31eb83d87039ec88934fdc47d8c312b892d
sum() { sha256sum "$dir/$1.json" | cut -d' ' -f1; }

hexf='(if . == null or . == "" then "-" else ascii_downcase end)'
shake='select(.parameterSet == "SLH-DSA-SHAKE-128s" or .parameterSet == "SLH-DSA-SHAKE-192s")'
ps='(.parameterSet | sub("SLH-DSA-SHAKE-"; ""))'

keygen() {
    jq -r ".testGroups[] | $shake | $ps as \$p | .tests[] |
      \"keygen \(\$p) \(.tcId) \(.skSeed|ascii_downcase) \(.skPrf|ascii_downcase) \(.pkSeed|ascii_downcase) \(.sk|ascii_downcase) \(.pk|ascii_downcase)\"" \
      "$dir/keyGen.json"
}

# sigGen: pure/internal, deterministic and hedged, first N of each group.
siggen() {
    jq -r --argjson n "$1" --argjson ni "$2" ".testGroups[] | $shake | $ps as \$p |
      select((.signatureInterface == \"external\" and .preHash == \"pure\") or .signatureInterface == \"internal\") |
      (if .signatureInterface == \"external\" then \"pure\" else \"internal\" end) as \$mode |
      (if .deterministic == true then \"det\" else \"hedged\" end) as \$det |
      (if \$mode == \"pure\" then \$n else \$ni end) as \$lim |
      .tests[:\$lim][] |
      \"sign \(\$p) \(.tcId) \(\$mode) \(\$det) \(.sk|ascii_downcase) \(.additionalRandomness | $hexf) \(.context | $hexf) \(.message | $hexf) \(.signature|ascii_downcase)\"" \
      "$dir/sigGen.json"
}

sigver() {
    jq -r ".testGroups[] | $shake | $ps as \$p |
      select((.signatureInterface == \"external\" and .preHash == \"pure\") or .signatureInterface == \"internal\") |
      (if .signatureInterface == \"external\" then \"pure\" else \"internal\" end) as \$mode |
      .tests[] |
      \"verify \(\$p) \(.tcId) \(\$mode) \(if .testPassed then 1 else 0 end) \(.pk|ascii_downcase) \(.context | $hexf) \(.message | $hexf) \(.signature|ascii_downcase)\"" \
      "$dir/sigVer.json"
}

# Wraps each record line into C string pieces of at most 3900 characters; the
# last piece of a line carries the newline.
wrap() {
    awk '{ s = $0; while (length(s) > 3900) { printf "    \"%s\",\n", substr(s, 1, 3900); s = substr(s, 3901) }
           printf "    \"%s\\n\",\n", s }'
}

cat <<HDR
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* SLH-DSA-SHAKE-128s and SLH-DSA-SHAKE-192s known-answer vectors. The comment
 * lines inside the text record the NIST ACVP source commit, the SHA-256 of each
 * source JSON file and the record layout. Each string holds at most 4000
 * characters so the table stays within the minimum string-literal length every
 * C compiler must accept; a line is the concatenation of consecutive strings up
 * to one ending in a newline. Regenerate with tests/gen_vectors.sh. */
static const char *const slhdsa_vector_pieces[] = {
    "# SLH-DSA known-answer vectors, NIST ACVP FIPS 205 internalProjection data.\n",
    "# Source repository: https://github.com/usnistgov/ACVP-Server\n",
    "# Upstream commit:   $commit\n",
    "# Source files and sha256 of the downloaded JSON:\n",
    "#   gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json\n",
    "#     $(sum keyGen)\n",
    "#   gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json\n",
    "#     $(sum sigGen)\n",
    "#   gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json\n",
    "#     $(sum sigVer)\n",
    "# Converted with jq/awk only; hex is lowercase; tcId is the upstream id; - is empty.\n",
    "# Selection: SHAKE-128s and SHAKE-192s groups. All keyGen cases. sigGen: the\n",
    "# first 4 pure (context-string) cases and the first 2 internal cases of each\n",
    "# deterministic and hedged group. sigVer: every pure and internal case,\n",
    "# including the expected-fail ones. HashSLH-DSA (preHash) groups are not used.\n",
    "# Records (space-separated):\n",
    "#   keygen P tcId skseed skprf pkseed sk pk\n",
    "#   sign   P tcId pure|internal det|hedged sk rand ctx msg sig\n",
    "#   verify P tcId pure|internal expected(1|0) pk ctx msg sig\n",
HDR
{ keygen; siggen 4 2; sigver; } | wrap
echo "};"
