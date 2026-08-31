<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Pull request

## What & why

<!-- What does this change, and what problem does it solve? If it fixes a
     bug, describe the failure scenario it closes. -->

## Proof

<!-- Paste the result lines, not adjectives: -->

- [ ] `make lint` — clean (no new gate violations)
- [ ] `make test` (or `make t-fast ONLY=service_state_driver`) — green
- [ ] New behavior is covered by a test (boundary/adversarial cases, not
      just the happy path)

## License agreement (required)

- [ ] I license this contribution under the **Apache License 2.0**
      (inbound = outbound, per
      [CONTRIBUTING.md](CONTRIBUTING.md#licensing-of-contributions)),
      and I have the right to submit this work.
- [ ] Any third-party code included is under a permissive license
      (MIT/BSD/ISC/Zlib/Blue Oak/Apache-2.0) with upstream notices
      preserved in `NOTICE` / `docs/ATTRIBUTIONS.md` — or this PR
      includes no third-party code.
