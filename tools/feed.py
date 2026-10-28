#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Inspect published SovaGrid server assets and prepare signed feed metadata.

This is an offline release-operator tool except for downloads of public release
assets. It never uploads or commits a feed and never creates a signing key.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request


REPO = Path(__file__).resolve().parents[1]
RELEASE_BASE = "https://github.com/sovagrid/sovagrid-blueprint/releases/download/"
ARCHIVE_NAME = "SovaGrid-server-source.tar.gz"
HOSTS = frozenset({"github.com", "release-assets.githubusercontent.com",
                   "objects.githubusercontent.com"})
CDN_HOSTS = HOSTS - {"github.com"}
VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
KEY_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
SAFE_NAME = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z")
COMPONENTS = frozenset({"sovagrid-blueprint", "sovagrid-hub", "sovagrid-web",
                        "sovagrid-agent", "sovagrid-vpn"})
REQUIRED = frozenset({"sovagrid-blueprint/run.sh", "sovagrid-blueprint/deploy/compose.yaml",
                      "sovagrid-hub/Dockerfile", "sovagrid-web/Dockerfile",
                      "sovagrid-web/deploy/Caddyfile.container",
                      "sovagrid-agent/deploy/sovagrid-agent.service",
                      "sovagrid-vpn/deploy/sovagrid-vpn-status.service"})
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
MAX_ARCHIVE = 64 * 1024**2
MAX_UNPACKED = 256 * 1024**2
MAX_FILES = 4096
MAX_FEED = 32 * 1024
MAX_RELEASES = 32
MAX_AGE = 30 * 86400
OPENSSL = shutil.which("openssl") or "/usr/bin/openssl"


class FeedError(Exception):
    pass


def digest(value: object) -> str:
    if not isinstance(value, str) or HASH.fullmatch(value) is None:
        raise FeedError("invalid SHA-256 digest")
    return value


def version(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str) or VERSION.fullmatch(value) is None:
        raise FeedError("invalid release version")
    return tuple(int(part) for part in value.split("."))


def archive_url(release_version: str) -> str:
    version(release_version)
    return RELEASE_BASE + "server-v" + release_version + "/" + ARCHIVE_NAME


def _safe_url(url: str, *, redirected: bool = False) -> None:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise FeedError("unsafe release URL") from exc
    if (parsed.scheme != "https" or parsed.hostname not in HOSTS or
            parsed.username is not None or parsed.password is not None or
            port not in (None, 443) or parsed.fragment or not parsed.path.startswith("/") or
            (parsed.query and not (redirected and parsed.hostname in CDN_HOSTS))):
        raise FeedError("unsafe release URL")


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _safe_url(newurl, redirected=True)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_published_asset(release_version: str) -> bytes:
    url = archive_url(release_version)
    _safe_url(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                                         SafeRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "SovaGrid-feed-publisher/1",
                                                  "Accept-Encoding": "identity",
                                                  "Cache-Control": "no-cache"})
    try:
        with opener.open(request, timeout=30) as response:
            _safe_url(response.geturl(), redirected=True)
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise FeedError("invalid release response")
            raw = response.read(MAX_ARCHIVE + 1)
    except (OSError, ValueError) as exc:
        raise FeedError("published release download failed") from exc
    if not 0 < len(raw) <= MAX_ARCHIVE:
        raise FeedError("published archive is empty or too large")
    return raw


def inspect_archive(release_version: str, raw: bytes, inspected_at: int | None = None) -> dict:
    url = archive_url(release_version)
    if not 0 < len(raw) <= MAX_ARCHIVE:
        raise FeedError("published archive is empty or too large")
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            manifest_member = None
            seen = set()
            directories = set()
            expanded = 0
            file_hashes = {}
            file_counts = {component: 0 for component in COMPONENTS}
            for member in archive:
                name = member.name.rstrip("/")
                if (name in seen or len(seen) >= MAX_FILES or not name.isascii() or
                        SAFE_NAME.fullmatch(name) is None or
                        any(part in (".", "..") for part in name.split("/")) or
                        (name != "sovagrid-bundle.json" and name.split("/", 1)[0] not in COMPONENTS) or
                        member.pax_headers or member.uid != 0 or member.gid != 0):
                    raise FeedError("archive contains unsafe member")
                seen.add(name)
                parent = name.rpartition("/")[0]
                if member.isdir():
                    if parent and parent not in directories:
                        raise FeedError("archive member precedes its parent directory")
                    if stat.S_IMODE(member.mode) != 0o755:
                        raise FeedError("archive contains unsafe directory mode")
                    directories.add(name)
                elif member.isfile():
                    if parent and parent not in directories:
                        raise FeedError("archive member precedes its parent directory")
                    if name != "sovagrid-bundle.json" and not parent:
                        raise FeedError("archive component must be a directory")
                    expanded += member.size
                    if (stat.S_IMODE(member.mode) not in (0o644, 0o755) or
                            member.size > 32 * 1024**2 or expanded > MAX_UNPACKED):
                        raise FeedError("archive contains unsafe file")
                    if name != "sovagrid-bundle.json":
                        stream = archive.extractfile(member)
                        if stream is None:
                            raise FeedError("archive member cannot be read")
                        file_hashes[name] = hashlib.sha256(stream.read(member.size + 1)).hexdigest()
                        file_counts[name.split("/", 1)[0]] += 1
                else:
                    raise FeedError("archive contains unsupported member")
                if name == "sovagrid-bundle.json":
                    manifest_member = member
            if (manifest_member is None or not manifest_member.isfile() or
                    not 0 < manifest_member.size <= 512 * 1024 or
                    stat.S_IMODE(manifest_member.mode) != 0o644):
                raise FeedError("archive has no unique regular bundle manifest")
            stream = archive.extractfile(manifest_member)
            if stream is None:
                raise FeedError("bundle manifest cannot be read")
            manifest = stream.read(512 * 1024 + 1)
    except (OSError, tarfile.TarError) as exc:
        raise FeedError("invalid published archive") from exc
    data = _json(manifest)
    if (set(data) != {"format", "components", "sha256"} or
            type(data["format"]) is not int or data["format"] != 1 or
            not isinstance(data["components"], dict) or set(data["components"]) != COMPONENTS or
            not isinstance(data["sha256"], dict) or data["sha256"] != file_hashes or
            not REQUIRED <= set(file_hashes)):
        raise FeedError("invalid bundle manifest")
    for name, component in data["components"].items():
        if (not isinstance(component, dict) or set(component) != {"commit", "file_count"} or
                not isinstance(component["commit"], str) or
                len(component["commit"]) != 40 or
                any(character not in "0123456789abcdef" for character in component["commit"]) or
                type(component["file_count"]) is not int or
                component["file_count"] != file_counts[name]):
            raise FeedError("invalid bundle component inventory")
    return {"format": 1, "version": release_version, "archive_url": url,
            "archive_sha256": hashlib.sha256(raw).hexdigest(), "archive_size": len(raw),
            "to_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            "inspected_at": int(time.time()) if inspected_at is None else inspected_at}


def _json(raw: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise FeedError("duplicate JSON key")
            result[key] = value
        return result
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise FeedError("invalid JSON") from exc
    if not isinstance(result, dict):
        raise FeedError("invalid JSON object")
    return result


def _encoded(value: dict) -> bytes:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > MAX_FEED:
        raise FeedError("feed exceeds 32 KiB")
    return raw


def _read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        return stream.read(limit + 1)


def _private_key(path: Path) -> Path:
    if path.is_relative_to(REPO) or (path.exists() and path.resolve().is_relative_to(REPO)):
        raise FeedError("private key must stay outside the feed repository")
    try:
        info = path.lstat()
    except OSError as exc:
        raise FeedError("signing key unavailable") from exc
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or
            info.st_uid != os.geteuid() or info.st_nlink != 1):
        raise FeedError("signing key must be an owned regular 0600 file")
    return path


def _openssl(*args: str) -> bytes:
    try:
        result = subprocess.run([OPENSSL, *args], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=15, check=False,
                                env={"PATH": "/usr/bin:/bin:/usr/local/bin", "LC_ALL": "C"})
    except (OSError, subprocess.SubprocessError) as exc:
        raise FeedError("OpenSSL unavailable") from exc
    if result.returncode != 0:
        raise FeedError("OpenSSL signing or verification failed")
    return result.stdout


def public_key(key: Path, expected_fingerprint: str) -> bytes:
    _private_key(key)
    der = _openssl("pkey", "-in", str(key), "-pubout", "-outform", "DER")
    if not der.startswith(SPKI_PREFIX) or len(der) != len(SPKI_PREFIX) + 32:
        raise FeedError("signing key is not Ed25519")
    if hashlib.sha256(der).hexdigest() != digest(expected_fingerprint):
        raise FeedError("signing key fingerprint differs from reviewed key")
    return der


def sign(raw: bytes, key: Path) -> bytes:
    with tempfile.TemporaryDirectory(prefix="sovagrid-sign-") as temporary:
        path = Path(temporary) / "feed.json"
        path.write_bytes(raw)
        signature = _openssl("pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(path))
    if len(signature) != 64:
        raise FeedError("invalid Ed25519 signature length")
    return signature


def verify(raw: bytes, signature: bytes, der: bytes) -> None:
    if len(raw) > MAX_FEED or len(signature) != 64:
        raise FeedError("invalid signed feed size")
    with tempfile.TemporaryDirectory(prefix="sovagrid-verify-") as temporary:
        root = Path(temporary)
        (root / "feed.json").write_bytes(raw)
        (root / "feed.sig").write_bytes(signature)
        (root / "key.der").write_bytes(der)
        _openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
                 "-inkey", str(root / "key.der"), "-sigfile", str(root / "feed.sig"),
                 "-in", str(root / "feed.json"))


def validate_feed(raw: bytes, key_id: str) -> dict:
    data = _json(raw)
    if (set(data) != {"format", "channel", "key_id", "issued_at", "expires_at", "releases"} or
            type(data["format"]) is not int or data["format"] != 1 or
            data["channel"] != "stable" or data["key_id"] != key_id or
            type(data["issued_at"]) is not int or type(data["expires_at"]) is not int or
            data["issued_at"] <= 0 or not 0 < data["expires_at"] - data["issued_at"] <= MAX_AGE or
            not isinstance(data["releases"], list) or not 1 <= len(data["releases"]) <= MAX_RELEASES):
        raise FeedError("invalid previous feed")
    prior_sequence, prior_version, prior_target = 0, (0, 0, 0), None
    seen_sources: set[str] = set()
    for release in data["releases"]:
        if (not isinstance(release, dict) or set(release) != {"sequence", "version",
                "from_manifest_sha256", "to_manifest_sha256", "archive_sha256", "archive_size"} or
                type(release["sequence"]) is not int or not 0 < release["sequence"] < 2**63 or
                type(release["archive_size"]) is not int or not 0 < release["archive_size"] <= MAX_ARCHIVE):
            raise FeedError("invalid previous release")
        source, target = digest(release["from_manifest_sha256"]), digest(release["to_manifest_sha256"])
        digest(release["archive_sha256"])
        current_version = version(release["version"])
        if (release["sequence"] <= prior_sequence or current_version <= prior_version or
                source == target or source in seen_sources or target in seen_sources or
                (prior_target is not None and source != prior_target)):
            raise FeedError("invalid previous release chain")
        seen_sources.add(source)
        prior_sequence, prior_version, prior_target = release["sequence"], current_version, target
    return data


def read_previous(feed_path: Path | None, signature_path: Path | None,
                  der: bytes, key_id: str) -> dict | None:
    if (feed_path is None) != (signature_path is None):
        raise FeedError("previous feed and signature must be supplied together")
    if feed_path is None:
        return None
    raw = feed_path.read_bytes()
    signature = signature_path.read_bytes()
    verify(raw, signature, der)
    return validate_feed(raw, key_id)


def _write_pair(directory: Path, raw: bytes, signature: bytes) -> None:
    if directory.is_symlink() or not directory.is_dir():
        raise FeedError("output directory must exist and must not be a symlink")
    for name in ("stable.json", "stable.json.sig"):
        if (directory / name).exists() or (directory / name).is_symlink():
            raise FeedError("output already contains signed feed files")
    (directory / "stable.json").write_bytes(raw)
    (directory / "stable.json.sig").write_bytes(signature)


def _issued(previous: dict | None, lifetime_days: int, issued_at: int | None) -> tuple[int, int]:
    if not 1 <= lifetime_days <= 30:
        raise FeedError("feed lifetime must be 1–30 days")
    now = int(time.time()) if issued_at is None else issued_at
    if now <= 0 or (previous is not None and now <= previous["issued_at"]):
        raise FeedError("issue time must advance; check UTC clock")
    return now, now + lifetime_days * 86400


def publish(inspection: dict, expected_archive_sha256: str, from_manifest_sha256: str,
            key_id: str, key: Path, expected_public_key_sha256: str, sequence: int,
            output_dir: Path, previous_feed: Path | None = None,
            previous_signature: Path | None = None, lifetime_days: int = 7,
            issued_at: int | None = None) -> dict:
    if not isinstance(key_id, str) or KEY_ID.fullmatch(key_id) is None:
        raise FeedError("invalid key ID")
    der = public_key(key, expected_public_key_sha256)
    previous = read_previous(previous_feed, previous_signature, der, key_id)
    if (not isinstance(inspection, dict) or set(inspection) != {"format", "version", "archive_url",
            "archive_sha256", "archive_size", "to_manifest_sha256", "inspected_at"} or
            type(inspection["format"]) is not int or inspection["format"] != 1 or
            type(inspection["archive_size"]) is not int or
            type(inspection["inspected_at"]) is not int or
            inspection["archive_url"] != archive_url(inspection["version"])):
        raise FeedError("invalid inspection document")
    expected = digest(expected_archive_sha256)
    if inspection["archive_sha256"] != expected:
        raise FeedError("reviewed archive pin differs from inspection")
    source = digest(from_manifest_sha256)
    target = digest(inspection["to_manifest_sha256"])
    if source == target or type(sequence) is not int or not 0 < sequence < 2**63:
        raise FeedError("invalid release transition")
    fresh = inspect_archive(inspection["version"], download_published_asset(inspection["version"]))
    for field in ("version", "archive_url", "archive_sha256", "archive_size", "to_manifest_sha256"):
        if fresh[field] != inspection[field]:
            raise FeedError("published asset differs from reviewed inspection")
    releases = [] if previous is None else list(previous["releases"])
    if previous is not None:
        last = releases[-1]
        if (sequence <= last["sequence"] or version(inspection["version"]) <= version(last["version"]) or
                source != last["to_manifest_sha256"]):
            raise FeedError("release does not extend the signed chain")
    release = {"sequence": sequence, "version": inspection["version"],
               "from_manifest_sha256": source, "to_manifest_sha256": target,
               "archive_sha256": expected, "archive_size": inspection["archive_size"]}
    releases.append(release)
    issued, expires = _issued(previous, lifetime_days, issued_at)
    value = {"format": 1, "channel": "stable", "key_id": key_id,
             "issued_at": issued, "expires_at": expires, "releases": releases}
    raw = _encoded(value)
    validate_feed(raw, key_id)
    signature = sign(raw, key)
    verify(raw, signature, der)
    _write_pair(output_dir, raw, signature)
    return value


def renew(key_id: str, key: Path, expected_public_key_sha256: str, previous_feed: Path,
          previous_signature: Path, output_dir: Path, lifetime_days: int = 7,
          issued_at: int | None = None) -> dict:
    der = public_key(key, expected_public_key_sha256)
    previous = read_previous(previous_feed, previous_signature, der, key_id)
    assert previous is not None
    issued, expires = _issued(previous, lifetime_days, issued_at)
    value = {**previous, "issued_at": issued, "expires_at": expires}
    raw = _encoded(value)
    signature = sign(raw, key)
    verify(raw, signature, der)
    _write_pair(output_dir, raw, signature)
    return value


def audit(feed_path: Path, signature_path: Path, public_key_der_path: Path,
          expected_public_key_sha256: str, key_id: str,
          expected_archive_sha256: str, expected_from_manifest_sha256: str,
          expected_version: str, now: int | None = None) -> dict:
    """Independently review a prepared pair with public material only.

    The latest signed release is compared with separately reviewed values and
    the exact already-published asset. This command does not write or sign.
    """
    if not isinstance(key_id, str) or KEY_ID.fullmatch(key_id) is None:
        raise FeedError("invalid key ID")
    expected_public_key_sha256 = digest(expected_public_key_sha256)
    expected_archive_sha256 = digest(expected_archive_sha256)
    expected_from_manifest_sha256 = digest(expected_from_manifest_sha256)
    version(expected_version)
    der = _read_bounded(public_key_der_path, len(SPKI_PREFIX) + 32)
    if (len(der) != len(SPKI_PREFIX) + 32 or not der.startswith(SPKI_PREFIX) or
            hashlib.sha256(der).hexdigest() != expected_public_key_sha256):
        raise FeedError("public key differs from reviewed fingerprint")
    raw = _read_bounded(feed_path, MAX_FEED)
    signature = _read_bounded(signature_path, 64)
    verify(raw, signature, der)
    value = validate_feed(raw, key_id)
    now = int(time.time()) if now is None else now
    if value["issued_at"] > now + 300 or value["expires_at"] <= now:
        raise FeedError("signed feed is not current")
    release = value["releases"][-1]
    if (release["version"] != expected_version or
            release["from_manifest_sha256"] != expected_from_manifest_sha256 or
            release["archive_sha256"] != expected_archive_sha256):
        raise FeedError("signed release differs from independently reviewed values")
    inspected = inspect_archive(expected_version, download_published_asset(expected_version))
    if (release["archive_sha256"] != inspected["archive_sha256"] or
            release["archive_size"] != inspected["archive_size"] or
            release["to_manifest_sha256"] != inspected["to_manifest_sha256"]):
        raise FeedError("published asset differs from signed release")
    return {"key_id": key_id, "public_key_sha256": expected_public_key_sha256,
            "issued_at": value["issued_at"], "expires_at": value["expires_at"],
            "release": release}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    inspection = subcommands.add_parser("inspect", help="hash the exact public release asset")
    inspection.add_argument("--version", required=True)
    inspection.add_argument("--output", type=Path, required=True)
    for name in ("publish", "renew"):
        command = subcommands.add_parser(name)
        command.add_argument("--key-id", required=True)
        command.add_argument("--private-key", type=Path, required=True)
        command.add_argument("--expected-public-key-sha256", required=True)
        command.add_argument("--previous-feed", type=Path)
        command.add_argument("--previous-signature", type=Path)
        command.add_argument("--output-dir", type=Path, required=True)
        command.add_argument("--lifetime-days", type=int, default=7)
    publish_parser = subcommands.choices["publish"]
    publish_parser.add_argument("--inspection", type=Path, required=True)
    publish_parser.add_argument("--expected-archive-sha256", required=True)
    publish_parser.add_argument("--from-manifest-sha256", required=True)
    publish_parser.add_argument("--sequence", type=int, required=True)
    audit_parser = subcommands.add_parser("audit", help="verify a prepared pair without a signing key")
    audit_parser.add_argument("--feed", type=Path, required=True)
    audit_parser.add_argument("--signature", type=Path, required=True)
    audit_parser.add_argument("--public-key-der", type=Path, required=True)
    audit_parser.add_argument("--expected-public-key-sha256", required=True)
    audit_parser.add_argument("--key-id", required=True)
    audit_parser.add_argument("--expected-archive-sha256", required=True)
    audit_parser.add_argument("--expected-from-manifest-sha256", required=True)
    audit_parser.add_argument("--expected-version", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            result = inspect_archive(args.version, download_published_asset(args.version))
            if args.output.exists() or args.output.is_symlink():
                raise FeedError("inspection output already exists")
            args.output.write_bytes(_encoded(result))
            print(json.dumps(result, sort_keys=True))
        elif args.command == "publish":
            result = publish(_json(args.inspection.read_bytes()), args.expected_archive_sha256,
                             args.from_manifest_sha256, args.key_id, args.private_key,
                             args.expected_public_key_sha256, args.sequence, args.output_dir,
                             args.previous_feed, args.previous_signature, args.lifetime_days)
            print("Prepared signed release", result["releases"][-1]["version"],
                  "sequence", result["releases"][-1]["sequence"])
        elif args.command == "renew":
            if args.previous_feed is None or args.previous_signature is None:
                raise FeedError("renew requires a previous signed feed")
            result = renew(args.key_id, args.private_key, args.expected_public_key_sha256,
                           args.previous_feed, args.previous_signature, args.output_dir,
                           args.lifetime_days)
            print("Prepared signed feed renewal at UTC epoch", result["issued_at"])
        else:
            result = audit(args.feed, args.signature, args.public_key_der,
                           args.expected_public_key_sha256, args.key_id,
                           args.expected_archive_sha256, args.expected_from_manifest_sha256,
                           args.expected_version)
            print(json.dumps(result, sort_keys=True))
    except (FeedError, OSError) as exc:
        print("SOVAGRID_FEED_REFUSE:" + str(exc), file=sys.stderr)
        return 40
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
