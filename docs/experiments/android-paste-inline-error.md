<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Paste correction

Unrecognized text and unreadable Z23-shaped codes stay in the protected Paste
editor with an explanatory result and the original text available for correction.
A recognized result follows its existing review path. The editor waits for the
worker to finish before enabling another Review; a failed text update retains
the result for a later UI tick. Already-paired laptop codes retain their specific
notice. The scan tests, Android ARM64 build, complexity and hardening checks
passed.

On the previously released Android application, a public invalid pasted code
returned Home with a notice that displaced the Home controls. An isolated API 36
simulator with ARM translation exercised the change at 1080x2160, density 540
and font scale 1.5. Invalid text and an unreadable fleet-shaped code stayed in
the editor with Review available. An injected first text-update failure was
followed by a successful update. The unreadable code was edited to a verified
synthetic invitation, which opened the synthetic manager review; Cancel returned
Home. Review and Cancel were visible with the keyboard open.

A separate synthetic preview was held while Android Back returned Home. Its
late cancellation did not reopen the review. On immediate Paste reentry, the
field and Review were both enabled, and a further invalid submission completed
inline. The fixture refused node, wallet and network operations. These sampled
simulator observations do not establish real fleet admission, a payment, or
physical-device behavior of the new editor.
