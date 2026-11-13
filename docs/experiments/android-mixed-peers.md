<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android peer network choice

The default keeps onion-only outbound connections. An explicit saved choice
allows direct peers alongside Tor on the next node start. Missing or invalid
preferences retain onion-only mode. Direct peers can see the phone IP address.

The Android app host suite passed with the Android SDK configured. Its log
SHA-256 was `b22bffcbaa273ff1d96df674f9057d4a4fec09da7f7e1afb0db2040462107ca9`.
The Android ARM64 native app library compiled with NDK r30 after the pinned
vendor archives passed their provenance check. Native build log SHA-256:
`65b6be6d83a6d2e9f9a3269969333a63cbf8d2249c4ee617e5cfa671560ab0c3`.
Phone interaction and actual peer connections remain unmeasured.
