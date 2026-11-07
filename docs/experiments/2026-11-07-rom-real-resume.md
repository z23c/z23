<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# ROM crash resume with a real state bundle

The opt-in `rom_fetch` fixture copies a supplied public bundle into an isolated directory, verifies its 62-chunk identity, interrupts a verified download after a durable journal update, and resumes in a fresh process. Its resumed peer uses the file-service session protocol and counts requests per chunk. This fixture does not prove production provider advertisement or retrieval.

Run the focused group with `ZCL_TEST_ROM_REAL_ARTIFACT` set to the public bundle path under the host build admission rail. The source bundle is opened read-only.

The bundle has 519831552 bytes and SHA3-256 `d8ea5864b4c5c89ce2d63c162b8291204312a49c8bd46faa4508f85ebc77f692`. Its transfer chunk root is `307c73a99954f493af67b91964acbd6fff32a2416d5fe9bb99c063eec9637cf3`. The separate checkpoint state root is `629271f1ce0cb26c035dca76ee1d65d1cc0421628df0261b8078ea6103284ae0`.

On 2026-11-07 the focused group passed with no skips. The killed client had one durable chunk; the resumed client fetched the other 61, verified the complete file, and removed both sidecars. Server accounting recorded no request for the retained chunk and exactly one request for each missing chunk. The baseline focused group also passed with no skips. An earlier opt-in attempt failed because its expected digest and root were incorrect; the corrected identities above were checked independently before the passing run.

```sh
ZCL_TEST_ROM_REAL_ARTIFACT=/path/to/public-bundle.sqlite \
  devbuild --wait --project z23 --class normal make t-fast-exact ONLY=rom_fetch
```
