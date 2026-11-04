<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android update signer guard

An isolated development keystore and a re-signed fixture APK exercised the signer checks. A missing keystore with an expected digest was refused without creating a key; an invalid digest was refused. The matching APK certificate passed and a different expected digest failed. A verifier failure was refused even when its output contained the expected digest. No device was updated.
