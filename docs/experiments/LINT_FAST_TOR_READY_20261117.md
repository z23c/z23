<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Standalone fast lint Tor readiness

A fresh checkout ran standalone fast lint before Tor archives were ready. The
vendor provenance gate failed; the combined fast-lint and preflight target
already prepared Tor when a selected gate required it.

Standalone fast lint now selects the existing Tor readiness prerequisite when
its selected gates include vendor or Tor provenance, in both serial and
parallel modes. Other selected gates do not introduce this prerequisite. The
provenance gates remain responsible for their existing hard checks.

The isolated Makefile fixture checks readiness ordering for both provenance
gates in both modes and checks that an unrelated gate does not prepare Tor.
Focused tests and native proof: not yet run for this change.
