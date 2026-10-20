<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Attestation acceptance wrapper: POSIX shell qualification

Date: 2026-10-20. Base: e727190b566cdacd52081247d3f6bd65159f0cf2.
Contributor: CesareFI; [public submission](https://github.com/z23c/z23/discussions/134#discussioncomment-19069479).
The original 706-byte patch has SHA256
71011190a95500418e7dee0c4510c10fab208bd2496dd04b64ee814e4b2f37ce.

The wrapper changes only its interpreter from Bash to POSIX sh and its options
from set -euo pipefail to set -eu. Directory resolution, both exported DHT
variables and the final explicit Bash delegation remain byte-identical. Mode
100755 is preserved. The existing shell allowlist row remains unchanged because
the gate counts shell paths, including POSIX sh scripts. The corresponding
work card now states that scope and acceptance accurately.

- `sh -n tools/dev/attestation_flight_acceptance.sh`: PASS.
- `git diff --check`: PASS.
- `make check-no-new-bash`: PASS, including its selftest; all 484 shell files
  were on the shrinking allowlist. The matching existing lint binary required
  no compilation for this check. The gate log has SHA256
  85fc4f2ab987757c25c6e02532f21e3dda88a40da4d605120645a88108c828dc.

The seven-daemon acceptance was not run. These static checks do not establish
that runtime journey. Full candidate qualification and landing remain pending.

<!-- claim: file-present tools/dev/attestation_flight_acceptance.sh -->
