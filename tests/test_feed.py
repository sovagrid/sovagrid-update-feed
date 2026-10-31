# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Disposable Ed25519 publisher fixtures checked by the independent verifier."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
import unittest
from unittest import mock
import contextlib

from tools import feed


BLUEPRINT = Path(os.environ.get("SOVAGRID_BLUEPRINT_ROOT", str(feed.REPO.parent / "sovagrid-blueprint")))
SOURCE = BLUEPRINT / "deploy" / "release_feed.py"


def fixture_archive(marker: str, *, include_directories: bool = True,
                    long_commits: bool = False, include_required: bool = True,
                    extra_files: dict[str, bytes] | None = None) -> bytes:
    files = {f"{name}/test.txt": (name + marker).encode() for name in sorted(feed.COMPONENTS)}
    if include_required:
        files.update({name: (name + marker).encode() for name in feed.REQUIRED})
    if extra_files:
        files.update(extra_files)
    files = dict(sorted(files.items()))
    commit_hash = hashlib.sha256 if long_commits else hashlib.sha1
    manifest = (json.dumps({"format": 1,
                            "components": {name: {"commit": commit_hash((name + marker).encode()).hexdigest(),
                                                  "file_count": sum(path.startswith(name + "/") for path in files)}
                                           for name in sorted(feed.COMPONENTS)},
                            "sha256": {name: hashlib.sha256(contents).hexdigest()
                                       for name, contents in files.items()}}, sort_keys=True) + "\n").encode()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        written_directories = set()
        for name, contents in files.items():
            parts = name.split("/")
            for depth in range(1, len(parts)):
                parent = "/".join(parts[:depth])
                if include_directories and parent not in written_directories:
                    directory = tarfile.TarInfo(parent + "/")
                    directory.type = tarfile.DIRTYPE
                    directory.mode = 0o755
                    archive.addfile(directory)
                    written_directories.add(parent)
            entry = tarfile.TarInfo(name)
            entry.mode = 0o644
            entry.size = len(contents)
            archive.addfile(entry, io.BytesIO(contents))
        entry = tarfile.TarInfo("sovagrid-bundle.json")
        entry.mode = 0o644
        entry.size = len(manifest)
        archive.addfile(entry, io.BytesIO(manifest))
    return output.getvalue()


class Publisher(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="sovagrid-feed-tests-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.key = self.root / "key.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(self.key)],
                       check=True, capture_output=True)
        self.key.chmod(0o600)
        self.der = subprocess.check_output(["openssl", "pkey", "-in", str(self.key),
                                            "-pubout", "-outform", "DER"])
        self.fingerprint = hashlib.sha256(self.der).hexdigest()
        self.now = int(time.time())
        self.archive1 = fixture_archive("one")
        self.archive2 = fixture_archive("two")

    def output(self, name: str) -> Path:
        path = self.root / name
        path.mkdir()
        return path

    def inspection(self, release_version: str, archive: bytes) -> dict:
        return feed.inspect_archive(release_version, archive, self.now - 30)

    def publish_one(self, archive: bytes, release_version: str, output: Path,
                    from_manifest: str = "a" * 64, sequence: int = 1,
                    previous: Path | None = None, issued_at: int | None = None) -> dict:
        inspection = self.inspection(release_version, archive)
        with mock.patch.object(feed, "download_published_asset", return_value=archive):
            return feed.publish(inspection, inspection["archive_sha256"], from_manifest,
                                "fixture-key", self.key, self.fingerprint, sequence, output,
                                None if previous is None else previous / "stable.json",
                                None if previous is None else previous / "stable.json.sig",
                                issued_at=self.now - 20 if issued_at is None else issued_at)

    def test_published_archive_pin_and_independent_verifier(self) -> None:
        first = self.output("first")
        value = self.publish_one(self.archive1, "0.5.2", first)
        self.assertEqual(value["releases"][0]["archive_sha256"],
                         hashlib.sha256(self.archive1).hexdigest())
        self.assertEqual(value["releases"][0]["archive_size"], len(self.archive1))
        self.assertEqual(value["releases"][0]["to_manifest_sha256"],
                         self.inspection("0.5.2", self.archive1)["to_manifest_sha256"])
        self.assertTrue(SOURCE.is_file(), "checkout sovagrid-blueprint for cross-repository verification")
        spec = importlib.util.spec_from_file_location("independent_release_verifier", SOURCE)
        assert spec and spec.loader
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        raw = (first / "stable.json").read_bytes()
        signature = (first / "stable.json.sig").read_bytes()
        with mock.patch.object(verifier, "TRUST_ANCHORS", {"fixture-key": self.der[len(feed.SPKI_PREFIX):]}), \
             mock.patch.object(verifier, "OPENSSL", feed.OPENSSL):
            checked = verifier.validate_manifest(raw, signature, "fixture-key",
                                                 verifier.empty_state(), self.now)
            self.assertEqual(verifier.select_release(checked, "a" * 64,
                                                     verifier.empty_state())["version"], "0.5.2")
        unpacked = self.root / "unpacked"
        archive_path = self.root / "published.tar.gz"
        archive_path.write_bytes(self.archive1)
        verifier.unpack_archive(archive_path, unpacked, value["releases"][0]["to_manifest_sha256"])

    def test_inspection_rejects_archives_server_cannot_install(self) -> None:
        without_directories = fixture_archive("missing-parents", include_directories=False)
        with self.assertRaisesRegex(feed.FeedError, "parent directory"):
            feed.inspect_archive("0.5.2", without_directories, self.now)
        without_required = fixture_archive("missing-required", include_required=False)
        with self.assertRaisesRegex(feed.FeedError, "invalid bundle manifest"):
            feed.inspect_archive("0.5.2", without_required, self.now)
        with_long_commits = fixture_archive("sha256-commits", long_commits=True)
        with self.assertRaisesRegex(feed.FeedError, "component inventory"):
            feed.inspect_archive("0.5.2", with_long_commits, self.now)

    def test_cli_inspection_and_publish_prepare_signed_pair(self) -> None:
        inspection_path = self.root / "inspection.json"
        output = self.output("cli")
        with mock.patch.object(feed, "download_published_asset", return_value=self.archive1), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(feed.main(["inspect", "--version", "0.5.2", "--output",
                                        str(inspection_path)]), 0)
            inspected = json.loads(inspection_path.read_text())
            self.assertEqual(feed.main(["publish", "--inspection", str(inspection_path),
                                        "--expected-archive-sha256", inspected["archive_sha256"],
                                        "--from-manifest-sha256", "a" * 64, "--sequence", "1",
                                        "--key-id", "fixture-key", "--private-key", str(self.key),
                                        "--expected-public-key-sha256", self.fingerprint,
                                        "--output-dir", str(output)]), 0)
        self.assertTrue((output / "stable.json").is_file())
        self.assertEqual((output / "stable.json.sig").stat().st_size, 64)

    def test_changed_published_asset_or_wrong_reviewed_pin_refused(self) -> None:
        inspection = self.inspection("0.5.2", self.archive1)
        with mock.patch.object(feed, "download_published_asset", return_value=self.archive2):
            with self.assertRaisesRegex(feed.FeedError, "published asset differs"):
                feed.publish(inspection, inspection["archive_sha256"], "a" * 64,
                             "fixture-key", self.key, self.fingerprint, 1, self.output("changed"),
                             issued_at=self.now - 20)
        with mock.patch.object(feed, "download_published_asset") as fetch:
            with self.assertRaisesRegex(feed.FeedError, "reviewed archive pin differs"):
                feed.publish(inspection, "f" * 64, "a" * 64,
                             "fixture-key", self.key, self.fingerprint, 1, self.output("wrongpin"),
                             issued_at=self.now - 20)
        fetch.assert_not_called()

    def test_public_only_audit_verifies_pair_and_published_archive(self) -> None:
        pair = self.output("audited")
        self.publish_one(self.archive1, "0.5.2", pair)
        public_key = self.root / "public.der"
        public_key.write_bytes(self.der)
        inspection = self.inspection("0.5.2", self.archive1)
        options = ["audit", "--feed", str(pair / "stable.json"),
                   "--signature", str(pair / "stable.json.sig"),
                   "--public-key-der", str(public_key),
                   "--expected-public-key-sha256", self.fingerprint,
                   "--key-id", "fixture-key",
                   "--expected-archive-sha256", inspection["archive_sha256"],
                   "--expected-from-manifest-sha256", "a" * 64,
                   "--expected-version", "0.5.2"]
        output = io.StringIO()
        with mock.patch.object(feed, "download_published_asset", return_value=self.archive1), \
             contextlib.redirect_stdout(output):
            self.assertEqual(feed.main(options), 0)
        self.assertEqual(json.loads(output.getvalue())["release"]["to_manifest_sha256"],
                         inspection["to_manifest_sha256"])
        with mock.patch.object(feed, "download_published_asset") as fetch, \
             self.assertRaisesRegex(feed.FeedError, "signed release differs"):
            feed.audit(pair / "stable.json", pair / "stable.json.sig", public_key,
                       self.fingerprint, "fixture-key", inspection["archive_sha256"],
                       "b" * 64, "0.5.2")
        fetch.assert_not_called()
        with mock.patch.object(feed, "download_published_asset", return_value=self.archive2), \
             self.assertRaisesRegex(feed.FeedError, "published asset differs"):
            feed.audit(pair / "stable.json", pair / "stable.json.sig", public_key,
                       self.fingerprint, "fixture-key", inspection["archive_sha256"],
                       "a" * 64, "0.5.2")
        with self.assertRaisesRegex(feed.FeedError, "public key differs"):
            feed.audit(pair / "stable.json", pair / "stable.json.sig", public_key,
                       "b" * 64, "fixture-key", inspection["archive_sha256"],
                       "a" * 64, "0.5.2")
        (pair / "stable.json.sig").write_bytes(bytes(64))
        with self.assertRaisesRegex(feed.FeedError, "OpenSSL signing or verification failed"):
            feed.audit(pair / "stable.json", pair / "stable.json.sig", public_key,
                       self.fingerprint, "fixture-key", inspection["archive_sha256"],
                       "a" * 64, "0.5.2")

    def test_published_audit_matches_exact_reviewed_pair(self) -> None:
        pair = self.output("live-audit")
        self.publish_one(self.archive1, "0.5.2", pair)
        public_key = self.root / "live-public.der"
        public_key.write_bytes(self.der)
        inspection = self.inspection("0.5.2", self.archive1)
        raw = (pair / "stable.json").read_bytes()
        signature = (pair / "stable.json.sig").read_bytes()
        options = ["audit-published", "--feed", str(pair / "stable.json"),
                   "--signature", str(pair / "stable.json.sig"),
                   "--public-key-der", str(public_key),
                   "--expected-public-key-sha256", self.fingerprint,
                   "--key-id", "fixture-key",
                   "--expected-archive-sha256", inspection["archive_sha256"],
                   "--expected-from-manifest-sha256", "a" * 64,
                   "--expected-version", "0.5.2"]
        with mock.patch.object(feed, "download_published_asset", return_value=self.archive1), \
             mock.patch.object(feed, "fetch_published_feed", side_effect=[raw, signature]) as fetch, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(feed.main(options), 0)
        self.assertEqual([call.args[0] for call in fetch.call_args_list],
                         [feed.FEED_URL, feed.FEED_URL + ".sig"])
        with mock.patch.object(feed, "download_published_asset", return_value=self.archive1), \
             mock.patch.object(feed, "fetch_published_feed", return_value=b"other"):
            with self.assertRaisesRegex(feed.FeedError, "differs from reviewed pair"):
                feed.audit_published(pair / "stable.json", pair / "stable.json.sig",
                                     public_key, self.fingerprint, "fixture-key",
                                     inspection["archive_sha256"], "a" * 64, "0.5.2")
        with self.assertRaisesRegex(feed.FeedError, "unexpected public feed URL"):
            feed.fetch_published_feed("https://example.invalid/stable.json", feed.MAX_FEED)
        with self.assertRaisesRegex(feed.FeedError, "published feed redirected"):
            feed.RefuseFeedRedirect().redirect_request(None, None, 302, "Found", {},
                                                        feed.FEED_URL)

    def test_append_and_renew_with_monotonic_utc_issue_time(self) -> None:
        first = self.output("one")
        old = self.publish_one(self.archive1, "0.5.2", first)
        second = self.output("two")
        new = self.publish_one(self.archive2, "0.5.3", second,
                               from_manifest=old["releases"][-1]["to_manifest_sha256"],
                               sequence=2, previous=first, issued_at=self.now - 10)
        self.assertEqual([item["version"] for item in new["releases"]], ["0.5.2", "0.5.3"])
        renewed = self.output("renewed")
        latest = feed.renew("fixture-key", self.key, self.fingerprint,
                            second / "stable.json", second / "stable.json.sig", renewed,
                            issued_at=self.now)
        self.assertEqual(latest["releases"], new["releases"])
        with self.assertRaisesRegex(feed.FeedError, "issue time must advance"):
            feed.renew("fixture-key", self.key, self.fingerprint,
                       second / "stable.json", second / "stable.json.sig",
                       self.output("stale"), issued_at=self.now - 11)
        with self.assertRaisesRegex(feed.FeedError, "invalid previous release chain"):
            broken = dict(new)
            broken["releases"] = [new["releases"][0], {**new["releases"][1],
                                                         "from_manifest_sha256": "e" * 64}]
            feed.validate_feed(feed._encoded(broken), "fixture-key")

    def test_publisher_rejects_chain_that_server_would_reject_as_cycle(self) -> None:
        first = self.output("first-cycle")
        value = self.publish_one(self.archive1, "0.5.2", first)
        source = value["releases"][0]["from_manifest_sha256"]
        target = value["releases"][0]["to_manifest_sha256"]
        cyclic = {**value, "releases": [
            value["releases"][0],
            {**value["releases"][0], "sequence": 2, "version": "0.5.3",
             "from_manifest_sha256": target, "to_manifest_sha256": source},
        ]}
        raw = feed._encoded(cyclic)
        with self.assertRaisesRegex(feed.FeedError, "invalid previous release chain"):
            feed.validate_feed(raw, "fixture-key")
        self.assertTrue(SOURCE.is_file(), "checkout sovagrid-blueprint for cross-repository verification")
        spec = importlib.util.spec_from_file_location("independent_cycle_verifier", SOURCE)
        assert spec and spec.loader
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        with mock.patch.object(verifier, "TRUST_ANCHORS", {"fixture-key": self.der[len(feed.SPKI_PREFIX):]}), \
             mock.patch.object(verifier, "OPENSSL", feed.OPENSSL):
            with self.assertRaisesRegex(verifier.Refused, "INVALID_RELEASE_ORDER"):
                verifier.validate_manifest(raw, feed.sign(raw, self.key), "fixture-key",
                                           verifier.empty_state(), self.now)

    def test_wrong_key_and_tampered_previous_signature_refused(self) -> None:
        first = self.output("first")
        old = self.publish_one(self.archive1, "0.5.2", first)
        with self.assertRaisesRegex(feed.FeedError, "fingerprint differs"):
            feed.public_key(self.key, "b" * 64)
        (first / "stable.json.sig").write_bytes(bytes(64))
        with self.assertRaisesRegex(feed.FeedError, "OpenSSL signing or verification failed"):
            self.publish_one(self.archive2, "0.5.3", self.output("next"),
                             from_manifest=old["releases"][-1]["to_manifest_sha256"],
                             sequence=2, previous=first, issued_at=self.now - 10)

    def test_previous_metadata_reads_are_bounded_before_verification(self) -> None:
        previous_feed = self.root / "oversized-feed.json"
        previous_sig = self.root / "oversized-feed.json.sig"
        previous_feed.write_bytes(b"x" * (feed.MAX_FEED + 1))
        previous_sig.write_bytes(bytes(64))
        with self.assertRaisesRegex(feed.FeedError, "invalid signed feed size"):
            feed.read_previous(previous_feed, previous_sig, self.der, "fixture-key")
        previous_feed.write_bytes(b"{}")
        previous_sig.write_bytes(bytes(65))
        with self.assertRaisesRegex(feed.FeedError, "invalid signed feed size"):
            feed.read_previous(previous_feed, previous_sig, self.der, "fixture-key")

    def test_url_key_and_bounds(self) -> None:
        self.assertEqual(feed.archive_url("0.5.2"),
                         "https://github.com/sovagrid/sovagrid-blueprint/releases/download/"
                         "server-v0.5.2/SovaGrid-server-source.tar.gz")
        for url in ("http://github.com/a", "https://attacker.example/a",
                    "https://github.com/a?token=x", "https://github.com:444/a"):
            with self.subTest(url=url), self.assertRaises(feed.FeedError):
                feed._safe_url(url)
        with self.assertRaisesRegex(feed.FeedError, "outside the feed repository"):
            feed._private_key(feed.REPO / "would-be-key.pem")
        with self.assertRaisesRegex(feed.FeedError, "invalid release version"):
            feed.archive_url("../0.5.2")
        with self.assertRaisesRegex(feed.FeedError, "archive is empty or too large"):
            feed.inspect_archive("0.5.2", b"")

    def test_inspector_rejects_unsupported_archive_member(self) -> None:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            member = tarfile.TarInfo("sovagrid-blueprint/escape")
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/shadow"
            archive.addfile(member)
        with self.assertRaisesRegex(feed.FeedError, "unsupported member"):
            feed.inspect_archive("0.5.2", output.getvalue())

    def test_inspector_accepts_systemd_template_and_rejects_traversal(self) -> None:
        template = "sovagrid-blueprint/deploy/sovagrid-external-agent-apply@.service"
        archive = fixture_archive("template", extra_files={template: b"[Unit]\n"})
        inspected = self.inspection("0.5.2", archive)
        self.assertEqual(inspected["archive_sha256"], hashlib.sha256(archive).hexdigest())

        traversal = fixture_archive(
            "traversal", extra_files={"sovagrid-blueprint/deploy/../escape@.service": b"bad"})
        with self.assertRaisesRegex(feed.FeedError, "unsafe member"):
            self.inspection("0.5.2", traversal)


if __name__ == "__main__":
    unittest.main()
