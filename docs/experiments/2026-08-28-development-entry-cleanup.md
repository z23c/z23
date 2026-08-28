<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Development entry cleanup — 2026-08-28

## Intention

Shorten the path from a fresh checkout to the public C23 node, remove obsolete
agent-specific and shell activation surfaces, and retain explicit platform
boundaries for Linux, WSL2, macOS, and native Windows.

## Observations

- Bare `make` selected `all`, linking the monolithic test harness and auxiliary
  tools even when a user requested only the public node.
- The save watcher carried an unreachable environment-supplied hot-swap command,
  result ingestion, and automatic reload fallback. Its public modes already
  refused every runtime publication path.
- Three ad hoc join probes, an unused ontology helper, two superseded work notes,
  and the always-refusing hot-swap wrapper had no live callers.
- The pipefail ratchet passed deleted tracked shell paths from `git ls-files`
  into `awk`, so a legitimate deletion could corrupt the scan result.

## Result

Bare `make` now builds `z23`; `make all` remains the explicit complete bundle.
The generic watcher is verification-only and the live hot-swap authority remains
the typed, allowlisted module path. The lint scanner excludes deleted tracked
files and its self-test proves that case. The getting-started guide now provides
one bounded four-job build path and states each platform's actual capability.

Measured at `2026-08-28T18:41:56-04:00`
(`2026-08-28T22:41:56Z`) on GCC 16.1.1, AMD Ryzen 7 PRO 8840U:

```text
make dev-watch-selftest                         PASS
make help-selftest doctor-selftest              PASS
check-hotswap-dev-only                          PASS
check-hotswap-swappable-shape                   PASS (62 READY leaves)
test_hotswap_loader                             groups_failed=0 self_skips=0
test_hotswap_simnet                             groups_failed=0 self_skips=0
test_make_lint_gates                            groups_failed=0 self_skips=0
make check-onion-pair-watch                     PASS
make check-pipefail-status-pipe                 PASS (406 scripts)
make lint                                       PASS (158/158 gates)
```

No production service, canonical datadir, consensus predicate, or custody path
was changed or exercised.

## Concurrent main integration

The cleanup was merged locally with the task/work transport added concurrently
to `origin/main`. Review of that intersection found and corrected three
fail-closed defects before publication:

- a read-only task board no longer opens or creates a caller-selected package
  store;
- record discovery applies local policy before its output limit, so a denied
  prefix cannot conceal an allowed record or disclose a pre-policy count; and
- a task pointer cannot remain publishable after its signed task expires.

Task goal projection now honors its documented bounded-prefix contract. Dormant
agent-scope text no longer implies an active authorization system, and an
unused scope-grant API was removed.

Measured at `2026-08-28T19:16:40-04:00`
(`2026-08-28T23:16:40Z`) on GCC 16.1.1, AMD Ryzen 7 PRO 8840U:

```text
task/DHT/hot-swap intersection                  PASS (23/23 groups)
                                                groups_failed=0 self_skips=0
zcode dht policy-prefix regression              PASS
make lint                                      PASS (158/158 gates)
```
