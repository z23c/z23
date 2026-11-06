<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Receive amount field during redraw

Date: 2026-11-06.

The Receive renderer keeps its amount field attached while the Receive page is
redrawn. This preserves the field's text, selection and input-method state as
other items change. Leaving Receive still clears the field.

<!-- claim: symbol-present zapp_wallet_ui_render apps/z23android/wallet_ui.c # Receive redraw entry point -->

A separate NativeActivity fixture exercised the renderer on a Pixel. It used a
controlled focus and keyboard request one second after launch, then changed its
Receive screen after 30 seconds and every 10 seconds thereafter. The fixture
used the real renderer and JNI helpers, and no wallet or node data.

| Observation | Baseline | Candidate |
| --- | --- | --- |
| Keyboard and focus after redraw | Keyboard hidden and field unfocused at refresh 3 | Keyboard visible and field focused at refresh 5 |
| Input after redraw | Not established | A physical `9` key tap entered `9` at refresh 8; text and focus remained at refresh 21 |
| Cursor insertion after redraw | `12345` | `123945` |

The cursor test entered `12345`, moved the cursor left twice, waited for a
redraw, and entered `9` without retapping the field. The before snapshot showed
`12345` and focus on refresh 1; the after snapshot followed refresh 2. The
cursor test used a separate fixture build. The keyboard test used the same
controlled focus setup for both builds. These observations test redraw; the keyboard test uses a
controlled keyboard precondition; they do not prove a physical tap opens the
production Receive field, nor do they exercise a production wallet.

SHA-256 identities for the tested artifacts:

- Baseline fixture APK: `e8877bb43b037ad7cf1a2cc7d064b053223d09ff7fde87ebad9fb6b4a8f543d1`.
- Candidate fixture APK: `f42cb355ae0c3c7ec410df24543855e9f5823b1a62dbed70b023a86d15d628ec`.
- Baseline cursor fixture APK: `a4d36d751baba10e48f19c155d1ed906be6bf3bc5371e51479639db03874ffcd`.
- Candidate cursor fixture APK: `f068a91b8002cee588d80212d6a951aea6fcc7a1c53c199810dcaa94309dd872`.
- Controlled-keyboard fixture source: `8b057a2bbbe5981ac0c5afc118e67a56e591c6eb7cf55d8dc7bebeb533c6b0b9`.
- Baseline renderer: `8e05b6124406828124307a57103006c91d28cb6f7734f03e80ed373b91d61268`.
- Measured candidate renderer before the complexity-only extraction: `ea5988f42394b3b929e7e65f26f217adcf9666f6eb69c433ed56acaf3b693618`.

The final renderer was tested with the same controlled-keyboard fixture. On the
phone, physical keypad input produced `12345` at refresh 1. After more than
30 seconds, a physical `9` key tap produced `123459` at refresh 3; the
keyboard and field remained visible at refresh 4. After moving the cursor left
twice and waiting 12 seconds, inputting `8` produced `1234859` at refresh 9.

- Final candidate fixture APK: `9c9cb9e8756b24d78edfb8ceaf3a0109a552b46d8ff7d398e9d017daa7313941`.
- Final candidate renderer: `728e7eaa9d46936e55b1c9778796291d10ee51c36a6fade0f5e1dab970b69989`.

A production Receive tap and keyboard walkthrough, empty-draft behavior, and
page-change draft clearing remain unmeasured by this fixture run. The fixture
and APKs are retained as local experiment artifacts.
