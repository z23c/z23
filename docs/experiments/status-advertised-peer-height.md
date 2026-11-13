<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Advertised peer height

2026-11-13: A peer survey using handshake height alone reported 3,318,238
while connected peers reported a best height of 3,318,273. A focused fixture
uses a handshake height of 105 and a reported best height of 1,000,000, with a
local block height of 100 and validated header height of 110.

With the production change reversed, both focused groups failed: the full
status fixture reported 105 instead of 1,000,000, and the peer survey fixture
failed its first case. With the change restored, both groups passed with no
skips. The full status fixture checks that the peer height remains labeled
untrusted and that the validated target and sync gap remain 110 and 10.

The focused command was:

```sh
DEVBUILD_CLASS=normal devbuild --wait make -j8 t-fast-exact ONLY=test_status_frontdoor,test_native_api_contract
```
