#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_installed_acceptance_tools.sh — the public installed-Commons target
# must run with every optional variable unset.
#
# `make c23-commons-installed-acceptance` installs an ordinary product into a
# throwaway prefix and then hands that prefix to the canonical DHT harness.
# The harness refuses to start a single node until every binary it names is
# executable. One of those binaries — its own assertion tool,
# arena_product_journey_c23 — was installed only when
# C23_BETA_INSTALL_ARENA_RUNNER=1, while DHT_ACCEPTANCE_C23 was pointed at the
# prefix unconditionally. So the public target died on the harness's own
# precondition before any composition hook ran, and passed only for whoever
# knew the undocumented flag. A flag that the documented command must be given
# is not optional; it is a missing install.
#
# The invariant, DERIVED on both sides so neither list is hand-written here:
#
#   every binary tools/dev/zcode_dht_acceptance.sh tests with `[ -x ]` before
#   it starts a node must be placed in the install prefix by
#   tools/dev/c23_commons_beta_acceptance.sh OUTSIDE every conditional.
#
# A harness that starts naming a new required binary trips this gate until the
# installed lane installs it. Binaries the harness does not name — arena_runner
# and zclassic23-dev, read only by the arena journey hook — are genuinely
# optional, stay behind their flag, and this gate says nothing about them.
#
# Mode is always FAIL (no baseline): a required binary behind an optional flag
# is never something to grandfather.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-installed-acceptance-tools "$@"
