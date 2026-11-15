<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android node details copy

Node details use shorter labels while preserving the existing sync predicates,
last-check qualification and separation from wallet scanning. The focused app
host suite passed on 2026-11-14, including unknown references, paused states,
privacy markers and a node ahead of its reference. Log SHA-256:
`d40be9cff06b4a40b5ec9678f66d60670ff3efddf4eabe632f4300d2a30b1aa2`.
Phone presentation at larger text sizes remains unmeasured.

The first full lint failed because the expanded test exceeded the complexity
cap. The cases were split without changing assertions or the cap. The focused
complexity gate then passed; log SHA-256:
`82323a62b852d71f0a54f13012a93ef0d1d758505b1769b47db554d10624a2f5`.
The final focused host suite passed after the fixture split; log SHA-256:
`360478d9ef82ddf6829da5d5c771fcaf9a3e6d7662c6204497dc14198c181a52`.

On 2026-11-15, Node details added cooling and background-work wording for
gentle pace and an explicit cooling reason for paused sync. The app host
suite passed with normal, gentle and paused rendering assertions. Log
SHA-256: `6c598ddbb9d713e4f8ba95d13bee624810d24049d71899022e7737ea0f56dcc9`.
Phone presentation of this change is not yet verified.
