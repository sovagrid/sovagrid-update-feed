# SovaGrid update feed

This repository publishes signed release metadata for independent SovaGrid servers. The first stable transition is from server `v0.13.0` to [`v0.14.0`](https://github.com/sovagrid/sovagrid-blueprint/releases/tag/server-v0.14.0). A public Ed25519 trust anchor is pinned in the installed Blueprint source; the private signing key is held outside Git, CI, and managed servers. Cloning this repository does not enable automatic updates.

The verifier and its security contract live in [sovagrid-blueprint](https://github.com/sovagrid/sovagrid-blueprint/blob/main/RELEASE_FEED.md). This repository contains `stable.json` and its detached `stable.json.sig`; exact server archives remain GitHub release assets. The detached Ed25519 signature covers the original bytes of `stable.json`; servers must pin the reviewed public key in their installed code before accepting it. No server obtains its trust key from this feed.

Release metadata is kept separate from the server source bundle so that adding or updating the feed cannot change the source bundle's own SHA-256. An administrator enables the channel separately on each full-server installation in Web settings or a compatible Connect client. Until then, the one-candidate update timer remains available. A Hub with an external Agent uses its separate update path and cannot subscribe to this full-server feed yet.

## Reproducible publishing workflow

`tools/feed.py` prepares metadata from the **public, already published** `server-vMAJOR.MINOR.PATCH/SovaGrid-server-source.tar.gz` asset. It refuses arbitrary URLs and unauthenticated mirrors. `inspect` downloads that asset, checks the archive layout, required source paths and bundle hashes, and reports its byte count, SHA-256, and the SHA-256 of the `sovagrid-bundle.json` inside it. A release reviewer records the archive SHA-256 independently. `publish` requires that reviewed SHA-256, downloads the asset again, compares every pin with the inspection, verifies a previous signed feed when extending a chain, and signs the final JSON bytes. `renew` extends only the UTC validity window while preserving the release chain and its archive pins. Neither command uploads to GitHub. These archive checks do not run the complete server update preflight; test the exact release asset with that preflight on a disposable Ubuntu host before enabling the feed.

Example for a **later stable release**, after the key custody and independently recorded public fingerprint have been reviewed:

```sh
python3 tools/feed.py inspect --version 0.15.0 --output /secure/review/inspection.json
python3 tools/feed.py publish \
  --inspection /secure/review/inspection.json \
  --expected-archive-sha256 REVIEWED_PUBLIC_ASSET_SHA256 \
  --from-manifest-sha256 REVIEWED_INSTALLED_BUNDLE_MANIFEST_SHA256 \
  --previous-feed /secure/review/stable.json \
  --previous-signature /secure/review/stable.json.sig \
  --sequence 2 --key-id REVIEWED_KEY_ID \
  --private-key /secure/offline/release-signing-key.pem \
  --expected-public-key-sha256 REVIEWED_ED25519_SPKI_SHA256 \
  --output-dir /secure/review/candidate
```

An independent reviewer can check the prepared pair using only the reviewed
public key in DER SPKI format and separately recorded release values. `audit`
verifies the detached signature, key fingerprint, complete metadata chain,
UTC validity, and the latest release against the exact public asset. It does
not need the private key and does not modify files:

```sh
python3 tools/feed.py audit \
  --feed /secure/review/candidate/stable.json \
  --signature /secure/review/candidate/stable.json.sig \
  --public-key-der /secure/review/release-public.der \
  --expected-public-key-sha256 REVIEWED_ED25519_SPKI_SHA256 \
  --key-id REVIEWED_KEY_ID \
  --expected-archive-sha256 REVIEWED_PUBLIC_ASSET_SHA256 \
  --expected-from-manifest-sha256 REVIEWED_INSTALLED_BUNDLE_MANIFEST_SHA256 \
  --expected-version 0.15.0
```

The reviewer must get the fingerprint and asset SHA-256 through an independent
approval path; values copied from the candidate feed are not an independent
check. The command checks only the latest archive. Earlier entries in the
signed chain are schema and signature checked but their old assets are not
downloaded again.

After committing the approved `stable.json` and `stable.json.sig` together,
run the same command with `audit-published` in place of `audit`. It verifies
the signed local pair and public release asset again, then compares both
published files byte for byte with the approved pair at the exact feed URL
used by servers. It refuses redirects and other origins. This read-only check
needs no signing key and does not enable any server subscription.

For the next release, provide both `--previous-feed` and `--previous-signature` from the approved signed feed, use the prior release's `to_manifest_sha256` as `--from-manifest-sha256`, and increase sequence and version. To renew, use `renew` with the same key, verified prior pair, and a new empty output directory. Timestamp fields are Unix seconds in UTC; the machine's local timezone is irrelevant. The issue time must advance, the validity window is at most 30 days, and the server rejects feed time rollback and clock rollback greater than five minutes.

Review the exact generated bytes, asset pins, public-key fingerprint, and server-source release before committing `stable.json` and `stable.json.sig` together. Keep old signed feeds in Git history for audit. Publishing is a privileged release action: the signed archive can contain root-executed code. Do not commit private signing keys, tokens, credentials, or draft signed metadata here. The production signing key must remain outside managed servers and CI logs. A compromised signing key could authorize root-level server code; key custody and revocation require an independent release procedure before activation.

`.github/workflows/verify.yml` creates a **disposable** Ed25519 key in the runner's temporary directory, signs synthetic fixture archives, and checks the result with the independent Blueprint verifier. CI has no production signing key and cannot publish a production feed. Run the same checks locally with `python3 -m unittest discover -s tests -v` while the Blueprint checkout is beside this repository, or set `SOVAGRID_BLUEPRINT_ROOT` to its path.

## License and authorship

SovaGrid — Copyright (C) 2026 Jigokuraku01. Original material is licensed under [AGPL-3.0-only](LICENSE) with the author attribution term in [ATTRIBUTION.md](ATTRIBUTION.md). Preserve [NOTICE](NOTICE) when redistributing.
