#!/usr/bin/env python3
"""Validate and atomically publish a Plutonium catalog to the private S3 bucket."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


MAX_CATALOG_BYTES = 32 * 1024 * 1024
ALLOWED_PLANETS = {"claudesec", "copilotsec", "marketplace"}


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def load_catalog(path: Path) -> tuple[bytes, dict[str, Any], dict[str, int]]:
    payload = path.read_bytes()
    if not payload or len(payload) > MAX_CATALOG_BYTES:
        raise SystemExit("catalog must contain 1-33554432 bytes")
    try:
        raw = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("catalog is not valid UTF-8 JSON") from exc
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "records"}:
        raise SystemExit("catalog must contain only schema_version and records")
    if raw.get("schema_version") != 1 or not isinstance(raw.get("records"), list) or not raw["records"]:
        raise SystemExit("catalog schema_version or records are invalid")
    record_ids = []
    planets = []
    for record in raw["records"]:
        if not isinstance(record, dict) or not isinstance(record.get("record_id"), str):
            raise SystemExit("every catalog record must have a string record_id")
        if record.get("planet") not in ALLOWED_PLANETS:
            raise SystemExit("every catalog record must have a known planet")
        record_ids.append(record["record_id"])
        planets.append(record["planet"])
    if len(record_ids) != len(set(record_ids)):
        raise SystemExit("catalog record_id values must be unique")
    counts = dict(sorted(Counter(planets).items()))
    return payload, raw, counts


def load_manifest(
    path: Path,
    *,
    payload: bytes,
    record_count: int,
    now: datetime | None = None,
) -> tuple[str, str, str]:
    try:
        raw = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("manifest is not valid JSON") from exc
    metadata = raw.get("catalog", {}) if isinstance(raw, dict) else {}
    if (
        metadata.get("bytes") != len(payload)
        or metadata.get("sha256") != hashlib.sha256(payload).hexdigest()
        or metadata.get("record_count") != record_count
    ):
        raise SystemExit("manifest catalog metadata does not match catalog.json")
    published_at = raw.get("published_at")
    expires_at = raw.get("expires_at")
    source_commit = raw.get("source", {}).get("commit", "")
    if (
        not isinstance(published_at, str)
        or not isinstance(expires_at, str)
        or not isinstance(source_commit, str)
    ):
        raise SystemExit("manifest provenance is invalid")
    try:
        published = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
        expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit("manifest timestamps are invalid") from exc
    current = now or datetime.now(timezone.utc)
    if (
        published > current + timedelta(minutes=10)
        or expires < current - timedelta(minutes=10)
        or expires <= published
        or expires - published > timedelta(days=45)
    ):
        raise SystemExit("manifest is expired or outside the 45-day validity window")
    if source_commit and not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise SystemExit("manifest source commit is invalid")
    return published_at, expires_at, source_commit


def aws_put_object(
    *, region: str, bucket: str, key: str, body: Path, metadata: str | None = None
) -> None:
    command = [
        "aws",
        "--region",
        region,
        "s3api",
        "put-object",
        "--bucket",
        bucket,
        "--key",
        key,
        "--body",
        str(body),
        "--content-type",
        "application/json",
        "--cache-control",
        "no-store",
        "--server-side-encryption",
        "AES256",
    ]
    if metadata:
        command.extend(("--metadata", metadata))
    subprocess.run(command, check=True)


def publish(
    args: argparse.Namespace, *, now: datetime | None = None
) -> dict[str, Any]:
    catalog_path = args.catalog.resolve()
    payload, raw, counts = load_catalog(catalog_path)
    digest = hashlib.sha256(payload).hexdigest()
    published_at, expires_at, source_commit = load_manifest(
        args.manifest.resolve(),
        payload=payload,
        record_count=len(raw["records"]),
        now=now,
    )
    catalog_key = f"releases/{digest}/catalog.json"
    pointer = {
        "schema_version": 1,
        "catalog_key": catalog_key,
        "sha256": digest,
        "bytes": len(payload),
        "record_count": len(raw["records"]),
        "catalog_counts": counts,
        "published_at": published_at,
        "expires_at": expires_at,
        "source_commit": source_commit,
    }
    if args.dry_run:
        return pointer
    aws_put_object(
        region=args.region,
        bucket=args.bucket,
        key=catalog_key,
        body=catalog_path,
        metadata=f"sha256={digest}",
    )
    with tempfile.TemporaryDirectory(prefix="plutonium-catalog-publish-") as directory:
        pointer_path = Path(directory) / "current.json"
        pointer_path.write_bytes(canonical_json(pointer))
        aws_put_object(
            region=args.region,
            bucket=args.bucket,
            key="current.json",
            body=pointer_path,
            metadata=f"catalog-sha256={digest}",
        )
    return pointer


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "eu-central-1"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if not args.catalog.is_file():
        parser.error("--catalog must point to a file")
    if not args.manifest.is_file():
        parser.error("--manifest must point to a file")
    return args


def main(argv: list[str] | None = None) -> int:
    pointer = publish(parse_args(argv))
    json.dump(pointer, sys.stdout, ensure_ascii=False, sort_keys=True, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
