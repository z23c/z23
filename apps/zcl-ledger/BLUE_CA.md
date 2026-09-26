<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# User controlled Ledger Blue signing key

Ledger Blue warns when opening an unsigned custom app. BOLOS supports a
custom certificate authority (CA): the owner enrolls a secp256k1 public key,
then installs apps signed by its matching private key. Z23 implements this
path in C23 without Ledger Live, Python, or a network service at runtime.
The Blue firmware and its warning remain authoritative; an unsigned app is
never presented as signed by Z23.

Generate one CA key in a private directory outside the repository:

```sh
install -d -m 700 "$HOME/.local/share/z23"
build/zcl-ledger/zcl-blue-ca generate "$HOME/.local/share/z23/blue-ca.pem"
```

The command creates a new owner-only file and refuses to overwrite an
existing key. Z23 refuses to load a key file accessible to other users. Keep
the file backed up securely: it controls which custom apps the Blue trusts.
It is unrelated to the Ledger recovery words and must never be generated
from or replaced with them.

On Blue firmware 2.1, enter the device's **Recovery mode** before enrolling
the public key. Ledger restricts CA management to that mode. The normal home
screen rejects enrollment with status `6985`, leaving the CA unchanged. Use
the Blue's recovery controls; instructions for Nano buttons do not apply to
the Blue. Once the Blue is in Recovery mode, run:

```sh
build/zcl-ledger/zcl-blue-install /dev/hidrawN --ca-enroll \
  "$HOME/.local/share/z23/blue-ca.pem"
```

Approve only the expected custom CA prompt on the Blue. The name shown is
`Z23`. The command does not send the private key to the device. To install a
reviewed, pinned app with its signature, remove any previous app with the
same name, then run:

```sh
build/zcl-ledger/zcl-blue-install /dev/hidrawN --ca-install \
  "$HOME/.local/share/z23/blue-ca.pem" app.bin
```

The installer hashes the Blue target ID, the exact create-app parameters,
the image bytes, and the app parameters in the order BOLOS verifies. It signs
that digest with ECDSA and includes the signature in the commit command.
The binary SHA-256 allowlist still applies before USB access.

To remove the custom CA, first delete apps installed through it, enter
Recovery mode, then use `zcl-blue-install /dev/hidrawN --ca-reset`.
[Ledger's firmware announcement](https://www.ledger.com/new-ledger-blue-firmware-version-2-1)
specifies the recovery-mode restriction. [Ledger's developer guidance](https://github.com/LedgerHQ/ledger-dev-doc/blob/master/source/userspace/debugging.rst)
states that enrolling a custom CA makes the device fail Ledger's Genuine
Check until the CA and its apps are removed. This is a device trust change,
not a change to the Ledger recovery words.

The CA path is experimental on the connected Blue until a signed app opens
without the BOLOS warning and can exit normally. A successful manager APDU
alone does not prove the warning is gone.
