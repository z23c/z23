<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Fleet mailbox discovery

`fleet.steer.brief` distinguishes historically observed `agents` from a
`mailbox_directory` of configured outbound box labels. The directory is a
bounded local snapshot of the verified roster, not a receiver-liveness or
delivery observation. Local, broadcast and imported-reference routes are not
enumerated; an absent label is not proof that an address is invalid.

The operator or a validated grant with send scope can see labels. A brief-only
grant sees `withheld` and no labels. Unreadable or unverifiable roster data,
overflow or unknown local identity yields `unknown`, never a partial complete
list. A verified list beyond the cap or reduced to fit the reply reports
`truncated`; budget cuts are counted in `budget_truncated.mailbox_directory`.
The observation time is the brief's own local time. No peer is contacted.

The checked-roster and scoped brief fixtures cover complete, truncated,
unknown and withheld states, including a populated forward-page byte budget.
On source `194430a941612b9f3c7bb5ab039ff705ba9549f7`, the three previously
failing focused groups (`devagent_boardmail`, `fleet_steer`, and
`command_registry_catalog`) passed cold with zero failures, skips, unobserved
groups or load-flaky retries in 9.327 seconds. An earlier six-group run had
three failing groups; its other three passes were on the earlier source.

The development binary SHA-256 was
`04e14bc353a100ba572a08d1ba0f4781708ef4ad9e68659e141c05ce3c6a5e6d`.
A local brief reported a complete two-label checked signer-bearing roster;
this does not represent all fleet-machine rows. The positional command
description parsed at 2,786 bytes. Full candidate proof: NOT RUN.

A queued message is not a receiver acknowledgment, and missing replies do not establish their cause.
