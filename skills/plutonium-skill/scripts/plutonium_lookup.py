#!/usr/bin/env python3
"""Fetch, verify, and query the signed Plutonium public catalog."""

from __future__ import annotations

import argparse
import base64
import binascii
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse, urlunparse


VERSION = "0.1.0"
SKILL_ROOT = Path(__file__).resolve().parent.parent
TRUST_PATH = SKILL_ROOT / "references" / "trust.json"
PUBLIC_KEY_PATH = SKILL_ROOT / "references" / "catalog-signing-public.pem"
EXPECTED_PUBLIC_KEY_SHA256 = "5f08f28346541f07e3de4b938c5592730006bf168043c6ae3b9eabfe1e1c541c"
REMOTE_URL = "https://github.com/plutosecurity/plutonium-catalog-data.git"
TAG_PATTERN_TEXT = r"^catalog-v([0-9]{10})$"
TAG_PATTERN = re.compile(TAG_PATTERN_TEXT)
TAG_REF_PREFIX = "refs/tags/"
EXPECTED_TREE = {
    "release/catalog.json",
    "release/manifest.json",
    "release/manifest.sig",
}
MANIFEST_PATH = "release/manifest.json"
SIGNATURE_PATH = "release/manifest.sig"
CATALOG_PATH = "release/catalog.json"
ALLOWED_RISKS = {"none", "low", "medium", "high", "critical"}
ALLOWED_PRINCIPLE_STATUSES = {"pass", "not_applicable", "needs_review", "fail"}
ALLOWED_PLANETS = {"claudesec", "copilotsec", "marketplace"}
ALLOWED_TYPES = {
    "connector",
    "desktop_extension",
    "interactive_connector",
    "mcp",
    "plugin",
    "skill",
    "web_connector",
}
ALLOWED_ASSESSMENT_KINDS = {"risk_rating", "trusted_membership"}
PLANET_RULES = {
    "claudesec": {
        "types": {"web_connector", "interactive_connector", "desktop_extension", "plugin"},
        "assessment_kind": "risk_rating",
        "identity": "uuid",
    },
    "copilotsec": {
        "types": {"connector", "plugin"},
        "assessment_kind": "risk_rating",
        "identity": "id",
    },
    "marketplace": {
        "types": {"connector", "mcp", "plugin", "skill"},
        "assessment_kind": "trusted_membership",
        "identity": "id",
    },
}
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
TYPE_LABELS = {
    "connector": "Connector",
    "web_connector": "Web Connector",
    "interactive_connector": "Interactive Connector",
    "desktop_extension": "Desktop Extension",
    "mcp": "MCP Server",
    "plugin": "Plugin",
    "skill": "Skill",
}
TAG_CAPABILITY_DEFINITIONS = (
    ("shell_access", "Runs Shell Commands"),
    ("filesystem_access", "Reads/Writes Files"),
    ("network_access", "Calls External APIs"),
    ("database_access", "Queries Databases"),
    ("browser_control", "Controls Browser"),
    ("email_messaging", "Sends Messages as User"),
    ("financial_ops", "Handles Payments/Billing"),
    ("code_deployment", "Deploys Code/Infra"),
    ("reads_private_data", "Accesses Private Data"),
    ("deletes_data", "Can Delete Resources"),
    ("has_telemetry", "Tracks Usage / Telemetry"),
    ("anthropic_built", "Built by Anthropic"),
)
CAPABILITY_HIGHLIGHT_PRIORITY = (
    "deletes_data",
    "shell_access",
    "financial_ops",
    "code_deployment",
    "filesystem_access",
    "database_access",
    "reads_private_data",
    "network_access",
    "email_messaging",
    "browser_control",
    "has_telemetry",
    "anthropic_built",
)
MAX_QUERY_CHARS = 500
MAX_QUERY_BASE64_CHARS = 4 * ((MAX_QUERY_CHARS * 4 + 2) // 3)
SUBPROCESS_TIMEOUT = 30
MAX_REF_OUTPUT_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 1024
MAX_CATALOG_BYTES = 32 * 1024 * 1024
MAX_LEGACY_VALIDITY = timedelta(days=45)
CLOCK_SKEW = timedelta(minutes=10)
SAFE_EXECUTABLE_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_DID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")

PLANET_QUALIFIERS = {
    "market space": {"marketplace"},
    "marketplace": {"marketplace"},
    "microsoft 365": {"copilotsec"},
    "copilot": {"copilotsec"},
    "m365": {"copilotsec"},
    "claude": {"claudesec"},
}
TYPE_QUALIFIERS = {
    "desktop extension": {"desktop_extension"},
    "interactive connector": {"interactive_connector"},
    "remote connector": {"web_connector"},
    "web connector": {"web_connector"},
    "mcp server": {"mcp"},
    "connector": {"connector", "web_connector", "interactive_connector"},
    "extension": {"desktop_extension"},
    "plugin": {"plugin"},
    "skill": {"skill"},
    "dxt": {"desktop_extension"},
    "mcp": {"mcp"},
}

MANIFEST_KEYS = {
    "schema_version",
    "sequence",
    "release_tag",
    "published_at",
    "expires_at",
    "source",
    "catalog",
    "known_source_anomalies",
}
SOURCE_KEYS = {"repository", "commit", "input_file_count", "inputs_sha256"}
CATALOG_META_KEYS = {
    "path",
    "bytes",
    "sha256",
    "record_count",
    "catalog_counts",
    "type_counts",
    "assessment_counts",
}
RECORD_KEYS = {
    "record_id",
    "planet",
    "ecosystem",
    "type",
    "category",
    "name",
    "publisher",
    "id",
    "uuid",
    "route_dids",
    "source_occurrences",
    "description",
    "long_description",
    "assessment",
    "security_risks",
    "tags",
    "risky_tools",
    "capabilities",
    "tools_count",
    "source_code_reviewed",
    "analysis_method",
    "added_at",
    "last_scanned",
    "urls",
}
PRINCIPLE_KEYS = {"key", "label", "description", "status", "evidence"}
SECURITY_RISK_KEYS = {
    "risk_type",
    "severity",
    "title",
    "description",
    "evidence",
    "remediation_steps",
}
RISKY_TOOL_KEYS = {"name", "description", "risk"}
TOOL_RISK_KEYS = {"level", "category", "why", "recommendation"}
CAPABILITY_KEYS = {"name", "description"}
URL_KEYS = {"plutonium", "listing", "source", "repository", "homepage"}


class LookupError(RuntimeError):
    """A fail-closed error safe to reduce to a public reason code."""

    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def is_plain_int(value: Any) -> bool:
    return type(value) is int


def normalize_text(value: Any) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return " ".join("".join(ch if ch.isalnum() else " " for ch in text).split())


def normalize_url(value: Any) -> str:
    try:
        parsed = urlparse(str(value or "").strip())
        port = parsed.port
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    host = parsed.hostname.casefold() + (f":{port}" if port else "")
    path = re.sub(r"/+$", "", parsed.path or "") or "/"
    return urlunparse((parsed.scheme.casefold(), host, path, "", parsed.query, ""))


def has_phrase(text: str, phrase: str) -> bool:
    return bool(phrase and re.search(rf"(?:^| ){re.escape(phrase)}(?: |$)", text))


def parse_utc(value: Any) -> datetime:
    if not isinstance(value, str):
        raise LookupError("catalog_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timestamp has no timezone")
        return parsed.astimezone(timezone.utc)
    except (OverflowError, ValueError) as exc:
        raise LookupError("catalog_invalid") from exc


def clean_display(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split())
    text = "".join(
        character
        for character in text
        if not unicodedata.category(character).startswith("C")
    )
    if len(text) <= limit:
        return text
    shortened = text[: limit - 1].rsplit(" ", 1)[0].rstrip(" ,.;:-")
    return f"{shortened}…"


def subprocess_environment(kind: str) -> dict[str, str]:
    blocked_prefixes = ("GIT_", "OPENSSL_", "LD_", "DYLD_", "PYTHON")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(blocked_prefixes)
        and key not in {"BASH_ENV", "ENV", "SHELLOPTS"}
    }
    environment["PATH"] = SAFE_EXECUTABLE_PATH
    if kind == "git":
        environment.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": "/bin/false",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
            }
        )
    return environment


def trusted_executable(name: str) -> str:
    path = shutil.which(name, path=SAFE_EXECUTABLE_PATH)
    if not path or not Path(path).is_absolute():
        raise LookupError("environment_unsupported")
    return path


def run_command(
    arguments: list[str],
    *,
    cwd: Path | None = None,
    kind: str,
    timeout: int = SUBPROCESS_TIMEOUT,
    reason_code: str,
) -> bytes:
    try:
        completed = subprocess.run(
            arguments,
            cwd=cwd,
            env=subprocess_environment(kind),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LookupError(reason_code) from exc
    return completed.stdout


def git_arguments(*arguments: str) -> list[str]:
    return [
        trusted_executable("git"),
        "-c",
        "credential.helper=",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "transfer.fsckobjects=true",
        *arguments,
    ]


def load_trust() -> dict[str, Any]:
    try:
        raw = json.loads(TRUST_PATH.read_text(encoding="utf-8"))
        public_key = PUBLIC_KEY_PATH.read_bytes()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LookupError("skill_invalid") from exc
    expected_keys = {
        "schema_version",
        "repository",
        "tag_pattern",
        "public_key_sha256",
    }
    if not isinstance(raw, dict) or set(raw) != expected_keys:
        raise LookupError("skill_invalid")
    if (
        raw.get("schema_version") != 1
        or raw.get("repository") != REMOTE_URL
        or raw.get("tag_pattern") != TAG_PATTERN_TEXT
        or raw.get("public_key_sha256") != EXPECTED_PUBLIC_KEY_SHA256
        or sha256_bytes(public_key) != EXPECTED_PUBLIC_KEY_SHA256
    ):
        raise LookupError("skill_invalid")
    return {**raw, "public_key": public_key}


def discover_latest_tag() -> tuple[str, str, int]:
    output = run_command(
        git_arguments("ls-remote", "--refs", "--tags", REMOTE_URL, "refs/tags/catalog-v*"),
        kind="git",
        reason_code="network_unavailable",
    )
    if len(output) > MAX_REF_OUTPUT_BYTES:
        raise LookupError("catalog_invalid")
    candidates: list[tuple[int, str, str]] = []
    try:
        lines = output.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise LookupError("catalog_invalid") from exc
    for line in lines:
        parts = line.split("\t")
        if len(parts) != 2 or not SHA_RE.fullmatch(parts[0]):
            raise LookupError("catalog_invalid")
        ref = parts[1]
        if not ref.startswith(TAG_REF_PREFIX):
            raise LookupError("catalog_invalid")
        tag = ref[len(TAG_REF_PREFIX) :]
        match = TAG_PATTERN.fullmatch(tag)
        if not match:
            raise LookupError("catalog_invalid")
        candidates.append((int(match.group(1)), tag, parts[0]))
    if not candidates:
        raise LookupError("no_catalog_release")
    sequence, tag, advertised_object = max(candidates)
    return tag, advertised_object, sequence


def initialize_repository(root: Path) -> Path:
    repository = root / "repository.git"
    template = root / "empty-template"
    template.mkdir()
    run_command(
        git_arguments("init", "--bare", "--quiet", f"--template={template}", str(repository)),
        kind="git",
        reason_code="environment_unsupported",
    )
    return repository


def fetch_release(repository: Path, tag: str, advertised_object: str) -> str:
    ref = f"{TAG_REF_PREFIX}{tag}"
    run_command(
        git_arguments(
            "-C",
            str(repository),
            "fetch",
            "--quiet",
            "--no-tags",
            "--depth=1",
            REMOTE_URL,
            ref,
        ),
        kind="git",
        reason_code="network_unavailable",
    )
    fetched_object = run_command(
        git_arguments("-C", str(repository), "rev-parse", "--verify", "FETCH_HEAD"),
        kind="git",
        reason_code="catalog_invalid",
    ).decode("ascii").strip()
    if fetched_object != advertised_object:
        raise LookupError("catalog_invalid")
    commit = run_command(
        git_arguments(
            "-C", str(repository), "rev-parse", "--verify", "FETCH_HEAD^{commit}"
        ),
        kind="git",
        reason_code="catalog_invalid",
    ).decode("ascii").strip()
    if not SHA_RE.fullmatch(commit):
        raise LookupError("catalog_invalid")
    return commit


def verify_tree(repository: Path, commit: str) -> None:
    output = run_command(
        git_arguments("-C", str(repository), "ls-tree", "-r", "--full-tree", commit),
        kind="git",
        reason_code="catalog_invalid",
    )
    try:
        lines = output.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise LookupError("catalog_invalid") from exc
    paths: set[str] = set()
    for line in lines:
        match = re.fullmatch(r"(\d{6}) (\w+) ([0-9a-f]{40})\t(.+)", line)
        if not match or match.group(1) != "100644" or match.group(2) != "blob":
            raise LookupError("catalog_invalid")
        paths.add(match.group(4))
    if paths != EXPECTED_TREE:
        raise LookupError("catalog_invalid")


def read_blob(repository: Path, commit: str, path: str, max_bytes: int) -> bytes:
    object_name = f"{commit}:{path}"
    object_type = run_command(
        git_arguments("-C", str(repository), "cat-file", "-t", object_name),
        kind="git",
        reason_code="catalog_invalid",
    ).decode("ascii").strip()
    if object_type != "blob":
        raise LookupError("catalog_invalid")
    size_text = run_command(
        git_arguments("-C", str(repository), "cat-file", "-s", object_name),
        kind="git",
        reason_code="catalog_invalid",
    ).decode("ascii").strip()
    try:
        size = int(size_text)
    except ValueError as exc:
        raise LookupError("catalog_invalid") from exc
    if size < 1 or size > max_bytes:
        raise LookupError("catalog_invalid")
    payload = run_command(
        git_arguments("-C", str(repository), "cat-file", "blob", object_name),
        kind="git",
        reason_code="catalog_invalid",
        timeout=60,
    )
    if len(payload) != size:
        raise LookupError("catalog_invalid")
    return payload


def verify_signature(root: Path, manifest: bytes, signature: bytes, trust: dict[str, Any]) -> None:
    if len(signature) != 64 or len(manifest) > MAX_MANIFEST_BYTES:
        raise LookupError("verification_failed")
    openssl = trusted_executable("openssl")
    manifest_path = root / "manifest.json"
    signature_path = root / "manifest.sig"
    public_key_path = root / "catalog-signing-public.pem"
    manifest_path.write_bytes(manifest)
    signature_path.write_bytes(signature)
    public_key_path.write_bytes(trust["public_key"])
    run_command(
        [
            openssl,
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(public_key_path),
            "-rawin",
            "-in",
            str(manifest_path),
            "-sigfile",
            str(signature_path),
        ],
        kind="openssl",
        reason_code="verification_failed",
    )


def load_json(payload: bytes, reason_code: str) -> Any:
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LookupError(reason_code) from exc


def validate_manifest(
    raw: Any,
    *,
    tag: str,
    sequence: int,
    now: datetime,
) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != MANIFEST_KEYS:
        raise LookupError("catalog_invalid")
    if (
        not is_plain_int(raw.get("schema_version"))
        or raw["schema_version"] != 1
        or not is_plain_int(raw.get("sequence"))
        or raw["sequence"] != sequence
    ):
        raise LookupError("catalog_invalid")
    if raw.get("release_tag") != tag:
        raise LookupError("catalog_invalid")
    source = raw.get("source")
    catalog = raw.get("catalog")
    if (
        not isinstance(source, dict)
        or set(source) != SOURCE_KEYS
        or source.get("repository") != "plutosecurity/plutonium"
        or not isinstance(source.get("commit"), str)
        or not SHA_RE.fullmatch(source["commit"])
        or not is_plain_int(source.get("input_file_count"))
        or source["input_file_count"] < 1
        or not isinstance(source.get("inputs_sha256"), str)
        or not SHA256_RE.fullmatch(source["inputs_sha256"])
    ):
        raise LookupError("catalog_invalid")
    if (
        not isinstance(catalog, dict)
        or set(catalog) != CATALOG_META_KEYS
        or catalog.get("path") != CATALOG_PATH
        or not is_plain_int(catalog.get("bytes"))
        or not 1 <= catalog["bytes"] <= MAX_CATALOG_BYTES
        or not isinstance(catalog.get("sha256"), str)
        or not SHA256_RE.fullmatch(catalog["sha256"])
        or not is_plain_int(catalog.get("record_count"))
        or catalog["record_count"] < 1
    ):
        raise LookupError("catalog_invalid")
    for key in ("catalog_counts", "type_counts", "assessment_counts"):
        counts = catalog.get(key)
        if not isinstance(counts, dict) or any(
            not isinstance(name, str)
            or not is_plain_int(count)
            or count < 0
            for name, count in counts.items()
        ):
            raise LookupError("catalog_invalid")
    if set(catalog["catalog_counts"]) != ALLOWED_PLANETS:
        raise LookupError("catalog_invalid")
    if sum(catalog["catalog_counts"].values()) != catalog["record_count"]:
        raise LookupError("catalog_invalid")
    if not isinstance(raw.get("known_source_anomalies"), list):
        raise LookupError("catalog_invalid")
    published_at = parse_utc(raw.get("published_at"))
    expires_at = parse_utc(raw.get("expires_at"))
    if published_at > now + CLOCK_SKEW:
        raise LookupError("catalog_invalid")
    # Schema v1 signed an expiry window, but Plutonium releases are immutable
    # published snapshots. Keep validating that legacy field structurally; do
    # not turn elapsed wall-clock time into a loss of authenticity.
    if (
        expires_at <= published_at
        or expires_at - published_at > MAX_LEGACY_VALIDITY
    ):
        raise LookupError("catalog_invalid")
    return raw


def validate_string(value: Any, *, maximum: int, required: bool = False) -> str:
    if not isinstance(value, str) or (required and not value.strip()):
        raise LookupError("catalog_invalid")
    if len(value) > maximum or any(
        unicodedata.category(character).startswith("C") for character in value
    ):
        raise LookupError("catalog_invalid")
    return value


def validate_string_list(
    value: Any,
    *,
    count_maximum: int,
    item_maximum: int,
    unique: bool = False,
) -> list[str]:
    if not isinstance(value, list) or len(value) > count_maximum:
        raise LookupError("catalog_invalid")
    items = [
        validate_string(item, maximum=item_maximum, required=True) for item in value
    ]
    if unique and len(items) != len(set(items)):
        raise LookupError("catalog_invalid")
    return items


def validate_principles(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 50:
        raise LookupError("catalog_invalid")
    for principle in value:
        if not isinstance(principle, dict) or set(principle) != PRINCIPLE_KEYS:
            raise LookupError("catalog_invalid")
        validate_string(principle.get("key"), maximum=128, required=True)
        validate_string(principle.get("label"), maximum=500)
        validate_string(principle.get("description"), maximum=3000)
        validate_string(principle.get("evidence"), maximum=8000)
        if principle.get("status") not in ALLOWED_PRINCIPLE_STATUSES:
            raise LookupError("catalog_invalid")
    return value


def validate_security_risks(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 50:
        raise LookupError("catalog_invalid")
    for risk in value:
        if not isinstance(risk, dict) or set(risk) != SECURITY_RISK_KEYS:
            raise LookupError("catalog_invalid")
        risk_type = validate_string(risk.get("risk_type"), maximum=128)
        title = validate_string(risk.get("title"), maximum=500)
        severity = validate_string(risk.get("severity"), maximum=32)
        if severity and severity not in ALLOWED_RISKS:
            raise LookupError("catalog_invalid")
        if not risk_type and not title:
            raise LookupError("catalog_invalid")
        validate_string(risk.get("description"), maximum=6000)
        validate_string(risk.get("evidence"), maximum=12000)
        validate_string_list(
            risk.get("remediation_steps"), count_maximum=20, item_maximum=2500
        )
    return value


def validate_risky_tools(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 200:
        raise LookupError("catalog_invalid")
    for tool in value:
        if not isinstance(tool, dict) or set(tool) != RISKY_TOOL_KEYS:
            raise LookupError("catalog_invalid")
        validate_string(tool.get("name"), maximum=500, required=True)
        validate_string(tool.get("description"), maximum=3000)
        risk = tool.get("risk")
        if not isinstance(risk, dict) or set(risk) != TOOL_RISK_KEYS:
            raise LookupError("catalog_invalid")
        level = validate_string(risk.get("level"), maximum=32)
        if level and level not in ALLOWED_RISKS:
            raise LookupError("catalog_invalid")
        validate_string(risk.get("category"), maximum=128)
        validate_string(risk.get("why"), maximum=6000)
        validate_string(risk.get("recommendation"), maximum=4000)
    return value


def validate_capabilities(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 200:
        raise LookupError("catalog_invalid")
    for capability in value:
        if not isinstance(capability, dict) or set(capability) != CAPABILITY_KEYS:
            raise LookupError("catalog_invalid")
        validate_string(capability.get("name"), maximum=500, required=True)
        validate_string(capability.get("description"), maximum=3000)
    return value


def parse_http_url(value: Any, *, maximum: int, required: bool = False):
    text = validate_string(value, maximum=maximum, required=required)
    if not text:
        return None
    if any(character.isspace() for character in text):
        raise LookupError("catalog_invalid")
    try:
        parsed = urlparse(text)
        parsed.port
    except ValueError as exc:
        raise LookupError("catalog_invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise LookupError("catalog_invalid")
    return parsed


def validate_urls(value: Any, *, planet: str, route_dids: list[str]) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != URL_KEYS:
        raise LookupError("catalog_invalid")
    plutonium = parse_http_url(value.get("plutonium"), maximum=1000, required=True)
    assert plutonium is not None
    try:
        params = parse_qs(plutonium.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise LookupError("catalog_invalid") from exc
    expected_params = {
        "planet": [planet],
        "did": [params.get("did", [""])[0]],
        "utm_source": ["plutonium_analysis_skill"],
        "utm_medium": ["claude_skill"],
        "utm_campaign": ["ai_product_risk_assessment"],
    }
    if (
        plutonium.scheme != "https"
        or plutonium.hostname != "plutonium.pluto.security"
        or plutonium.port is not None
        or plutonium.path != "/detail.html"
        or plutonium.params
        or plutonium.fragment
        or params != expected_params
        or params["did"][0] not in route_dids
    ):
        raise LookupError("catalog_invalid")
    for key in URL_KEYS - {"plutonium"}:
        parse_http_url(value.get(key), maximum=3000)
    return value


def validate_record(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != RECORD_KEYS:
        raise LookupError("catalog_invalid")
    record_id = validate_string(record.get("record_id"), maximum=1000, required=True)
    planet = validate_string(record.get("planet"), maximum=100, required=True)
    if planet not in ALLOWED_PLANETS:
        raise LookupError("catalog_invalid")
    rules = PLANET_RULES[planet]
    item_type = validate_string(record.get("type"), maximum=128, required=True)
    if item_type not in ALLOWED_TYPES or item_type not in rules["types"]:
        raise LookupError("catalog_invalid")
    validate_string(record.get("name"), maximum=500, required=True)
    item_id = validate_string(record.get("id"), maximum=500, required=True)
    item_uuid = validate_string(record.get("uuid"), maximum=128)
    identity = item_uuid if rules["identity"] == "uuid" else item_id
    if not identity or record_id != f"{planet}:{identity}":
        raise LookupError("catalog_invalid")
    for key, maximum in (
        ("ecosystem", 200),
        ("category", 300),
        ("publisher", 500),
        ("description", 6000),
        ("long_description", 12000),
        ("analysis_method", 200),
        ("added_at", 100),
        ("last_scanned", 100),
    ):
        validate_string(record.get(key), maximum=maximum)
    routes = record.get("route_dids")
    if (
        not isinstance(routes, list)
        or not routes
        or len(routes) > 10
        or any(not isinstance(route, str) or not SAFE_DID_RE.fullmatch(route) for route in routes)
        or len(routes) != len(set(routes))
    ):
        raise LookupError("catalog_invalid")
    if (
        not is_plain_int(record.get("source_occurrences"))
        or record["source_occurrences"] != len(routes)
    ):
        raise LookupError("catalog_invalid")
    source_reviewed = record.get("source_code_reviewed")
    if source_reviewed is not True and source_reviewed is not False and source_reviewed is not None:
        raise LookupError("catalog_invalid")
    if not is_plain_int(record.get("tools_count")) or record["tools_count"] < 0:
        raise LookupError("catalog_invalid")
    assessment = record.get("assessment")
    if not isinstance(assessment, dict) or assessment.get("kind") not in ALLOWED_ASSESSMENT_KINDS:
        raise LookupError("catalog_invalid")
    if assessment["kind"] != rules["assessment_kind"]:
        raise LookupError("catalog_invalid")
    if assessment["kind"] == "risk_rating":
        if set(assessment) != {"kind", "level"} or assessment.get("level") not in ALLOWED_RISKS:
            raise LookupError("catalog_invalid")
    else:
        if (
            set(assessment) != {"kind", "status", "source_risk_level", "principles"}
            or assessment.get("status") != "trusted"
            or assessment.get("source_risk_level") not in ALLOWED_RISKS
        ):
            raise LookupError("catalog_invalid")
        validate_principles(assessment.get("principles"))
    validate_security_risks(record.get("security_risks"))
    validate_string_list(
        record.get("tags"), count_maximum=200, item_maximum=128, unique=True
    )
    validate_risky_tools(record.get("risky_tools"))
    validate_capabilities(record.get("capabilities"))
    validate_urls(record.get("urls"), planet=planet, route_dids=routes)
    return record


def validate_catalog(raw: Any, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "records"}:
        raise LookupError("catalog_invalid")
    if (
        not is_plain_int(raw.get("schema_version"))
        or raw["schema_version"] != 1
        or not isinstance(raw.get("records"), list)
    ):
        raise LookupError("catalog_invalid")
    records = [validate_record(record) for record in raw["records"]]
    metadata = manifest["catalog"]
    if len(records) != metadata["record_count"]:
        raise LookupError("catalog_invalid")
    record_ids = [record["record_id"] for record in records]
    if len(record_ids) != len(set(record_ids)):
        raise LookupError("catalog_invalid")
    if Counter(record["planet"] for record in records) != Counter(metadata["catalog_counts"]):
        raise LookupError("catalog_invalid")
    if Counter(record["type"] for record in records) != Counter(metadata["type_counts"]):
        raise LookupError("catalog_invalid")
    if Counter(record["assessment"]["kind"] for record in records) != Counter(
        metadata["assessment_counts"]
    ):
        raise LookupError("catalog_invalid")
    return records


def retrieve_catalog(now: datetime) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    trust = load_trust()
    tag, advertised_object, sequence = discover_latest_tag()
    with tempfile.TemporaryDirectory(prefix="plutonium-skill-") as temporary:
        root = Path(temporary)
        repository = initialize_repository(root)
        commit = fetch_release(repository, tag, advertised_object)
        verify_tree(repository, commit)
        manifest_bytes = read_blob(repository, commit, MANIFEST_PATH, MAX_MANIFEST_BYTES)
        signature = read_blob(repository, commit, SIGNATURE_PATH, MAX_SIGNATURE_BYTES)
        verify_signature(root, manifest_bytes, signature, trust)
        manifest = validate_manifest(
            load_json(manifest_bytes, "catalog_invalid"),
            tag=tag,
            sequence=sequence,
            now=now,
        )
        catalog_bytes = read_blob(
            repository,
            commit,
            CATALOG_PATH,
            min(MAX_CATALOG_BYTES, manifest["catalog"]["bytes"]),
        )
        if (
            len(catalog_bytes) != manifest["catalog"]["bytes"]
            or sha256_bytes(catalog_bytes) != manifest["catalog"]["sha256"]
        ):
            raise LookupError("verification_failed")
        records = validate_catalog(load_json(catalog_bytes, "catalog_invalid"), manifest)
    provenance = {
        "verification": "ed25519+sha256",
        "catalog_release": tag,
        "sequence": sequence,
        "catalog_commit": commit,
        "source_commit": manifest["source"]["commit"],
        "published_at": manifest["published_at"],
        "record_count": manifest["catalog"]["record_count"],
        "catalog_counts": manifest["catalog"]["catalog_counts"],
    }
    return records, provenance


def record_identifiers(record: dict[str, Any]) -> set[str]:
    identifiers = {
        str(record.get(key)).strip().casefold()
        for key in ("record_id", "id", "uuid")
        if isinstance(record.get(key), str) and record[key].strip()
    }
    for route in record["route_dids"]:
        identifiers.add(route.casefold())
        identifiers.add(f"{record['planet']}:{route}".casefold())
    for value in record["urls"].values():
        normalized = normalize_url(value)
        if normalized:
            identifiers.add(normalized.casefold())
    return identifiers


def identifier_from_query(query: str) -> str:
    normalized = normalize_url(query)
    if normalized:
        parsed = urlparse(normalized)
        if (
            parsed.scheme == "https"
            and parsed.hostname == "plutonium.pluto.security"
            and parsed.port is None
            and parsed.path == "/detail.html"
        ):
            try:
                params = parse_qs(
                    parsed.query, keep_blank_values=True, strict_parsing=True
                )
            except ValueError:
                return normalized.casefold()
            planet = params.get("planet", [""])[0]
            did = params.get("did", [""])[0]
            if (
                planet
                and did
                and len(params.get("planet", [])) == 1
                and len(params.get("did", [])) == 1
            ):
                return f"{planet}:{did}".casefold()
        return normalized.casefold()
    return query.strip().casefold()


def remove_phrase(text: str, phrase: str, *, count: int = 0) -> tuple[str, bool]:
    updated, replacements = re.subn(
        rf"(?:^| ){re.escape(phrase)}(?= |$)", " ", text, count=count
    )
    return " ".join(updated.split()), bool(replacements)


def consume_qualifiers(
    text: str, qualifiers: dict[str, set[str]]
) -> tuple[str, set[str] | None]:
    allowed: set[str] | None = None
    for phrase in sorted(qualifiers, key=lambda item: (-len(item.split()), -len(item), item)):
        text, matched = remove_phrase(text, phrase)
        if matched:
            choices = qualifiers[phrase]
            allowed = set(choices) if allowed is None else allowed & choices
    return text, allowed


def qualifiers_match_record(residual: str, record: dict[str, Any]) -> bool:
    residual, requested_planets = consume_qualifiers(residual, PLANET_QUALIFIERS)
    if requested_planets is not None and record["planet"] not in requested_planets:
        return False
    residual, requested_types = consume_qualifiers(residual, TYPE_QUALIFIERS)
    if requested_types is not None and record["type"] not in requested_types:
        return False
    return not residual


def candidate_accepts_qualifiers(query: str, record: dict[str, Any]) -> bool:
    name = normalize_text(record["name"])
    publisher = normalize_text(record["publisher"])

    residual, matched_name = remove_phrase(query, name, count=1)
    if matched_name:
        if publisher and publisher != name:
            residual, _ = remove_phrase(residual, publisher, count=1)
        if qualifiers_match_record(residual, record):
            return True

    # A publisher can contain the whole product name (for example, publisher
    # "Starburst Data" and product "Starburst"). Try removing the publisher
    # first, but still require a separate product-name occurrence.
    if publisher and publisher != name:
        residual, matched_publisher = remove_phrase(query, publisher, count=1)
        if matched_publisher:
            residual, matched_name = remove_phrase(residual, name, count=1)
            if matched_name and qualifiers_match_record(residual, record):
                return True
    return False


def qualified_candidates(query: str, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates = [record for record in records if has_phrase(query, normalize_text(record["name"]))]
    if not candidates:
        return []
    longest_name = max(len(normalize_text(record["name"])) for record in candidates)
    candidates = [
        record for record in candidates if len(normalize_text(record["name"])) == longest_name
    ]

    return [record for record in candidates if candidate_accepts_qualifiers(query, record)]


def find_matches(
    query: str, records: list[dict[str, Any]]
) -> tuple[str, list[dict[str, Any]], str]:
    identifier = identifier_from_query(query)
    normalized_url = normalize_url(query)
    explicit_identifier = bool(
        normalized_url
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            query.strip(),
            re.IGNORECASE,
        )
        or query.strip().casefold().startswith(
            tuple(f"{planet}:" for planet in ALLOWED_PLANETS)
        )
    )
    if explicit_identifier:
        matches = [record for record in records if identifier in record_identifiers(record)]
        if matches:
            return ("match" if len(matches) == 1 else "ambiguous"), matches, "stable_identifier"
        return "no_match", [], "unknown_identifier"

    normalized = normalize_text(query)
    if not normalized:
        return "no_match", [], "empty_query"
    exact = [record for record in records if normalize_text(record["name"]) == normalized]
    if exact:
        return ("match" if len(exact) == 1 else "ambiguous"), exact, "exact_name"
    qualified = qualified_candidates(normalized, records)
    if qualified:
        return (
            "match" if len(qualified) == 1 else "ambiguous",
            qualified,
            "qualified_name",
        )
    matches = [record for record in records if identifier in record_identifiers(record)]
    if matches:
        return ("match" if len(matches) == 1 else "ambiguous"), matches, "stable_identifier"
    return "no_match", [], "no_reliable_match"


def candidate_view(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": record["record_id"],
        "name": record["name"],
        "publisher": record["publisher"] or None,
        "type": record["type"],
        "type_label": TYPE_LABELS[record["type"]],
        "planet": record["planet"],
        "ecosystem": record["ecosystem"] or None,
    }


def suggestions(query: str, records: list[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
    scored: list[tuple[float, str, str, dict[str, Any]]] = []
    for record in records:
        name = normalize_text(record["name"])
        publisher = normalize_text(record["publisher"])
        aliases = [name]
        if publisher and publisher != name:
            aliases.extend((f"{publisher} {name}", f"{name} {publisher}"))
        score = max(difflib.SequenceMatcher(None, query, alias).ratio() for alias in aliases)
        if query in name or name in query:
            score = max(score, 0.8)
        if score >= 0.58:
            scored.append((score, name, record["record_id"], record))
    scored.sort(key=lambda row: (-row[0], row[1], row[2]))
    return [candidate_view(record) for _, _, _, record in scored[:limit]]


def capability_flags(record: dict[str, Any]) -> list[dict[str, str]]:
    """Return active capability-grid flags in the same fixed order as the site."""
    tags = set(record["tags"])
    return [
        {"key": tag, "label": label}
        for tag, label in TAG_CAPABILITY_DEFINITIONS
        if tag in tags
    ]


def capability_highlights(flags: list[dict[str, str]]) -> list[dict[str, str]]:
    """Prioritize high-impact active flags for the bounded compact response."""
    by_key = {flag["key"]: flag for flag in flags}
    return [
        by_key[key]
        for key in CAPABILITY_HIGHLIGHT_PRIORITY
        if key in by_key
    ][:3]


def match_view(record: dict[str, Any], details: bool) -> dict[str, Any]:
    risks = sorted(
        record["security_risks"],
        key=lambda risk: (
            RISK_ORDER.get(risk["severity"], 99),
            normalize_text(risk["title"] or risk["risk_type"]),
        ),
    )
    risky_tools = sorted(
        record["risky_tools"],
        key=lambda tool: (
            RISK_ORDER.get(tool["risk"]["level"], 99),
            normalize_text(tool["name"]),
        ),
    )
    flags = capability_flags(record)
    risky_tool_counts = Counter(
        tool["risk"]["level"]
        for tool in risky_tools
        if tool["risk"]["level"] != "none"
    )
    risky_tool_summary = {
        "total": sum(risky_tool_counts.values()),
        "critical": risky_tool_counts["critical"],
        "high": risky_tool_counts["high"],
        "medium": risky_tool_counts["medium"],
        "low": risky_tool_counts["low"],
    }
    risky_tool_highlights = [
        {
            "name": tool["name"],
            "level": tool["risk"]["level"],
            "category": tool["risk"]["category"],
        }
        for tool in risky_tools
        if tool["risk"]["level"] != "none"
    ][:3]
    critical_high_tools = [
        tool
        for tool in risky_tools
        if tool["risk"]["level"] in {"critical", "high"}
    ]
    critical_high_tool_highlights = [
        {
            "name": tool["name"],
            "level": tool["risk"]["level"],
            "category": tool["risk"]["category"],
        }
        for tool in critical_high_tools[:3]
    ]
    risk_evidence_count = sum(bool(risk["evidence"].strip()) for risk in risks)
    remediation_step_count = sum(len(risk["remediation_steps"]) for risk in risks)
    tool_recommendation_count = sum(
        bool(tool["risk"]["recommendation"].strip())
        for tool in risky_tools
        if tool["risk"]["level"] != "none"
    )
    assessment = dict(record["assessment"])
    principle_count = 0
    principle_concern_count = 0
    principle_evidence_count = 0
    if assessment["kind"] == "trusted_membership":
        principles = assessment.pop("principles")
        concerns = sorted(
            (
                principle
                for principle in principles
                if principle.get("status") in {"needs_review", "fail"}
            ),
            key=lambda principle: 0 if principle["status"] == "fail" else 1,
        )
        principle_count = len(principles)
        principle_concern_count = len(concerns)
        principle_evidence_count = sum(
            bool(principle["evidence"].strip()) for principle in principles
        )
        assessment["principle_summary"] = dict(
            sorted(Counter(item.get("status") for item in principles).items())
        )
        assessment["principle_count"] = principle_count
        assessment["principle_concern_count"] = principle_concern_count
        assessment["principle_evidence_count"] = principle_evidence_count
        if details:
            assessment["principle_concerns"] = concerns
        else:
            failures = [item for item in concerns if item["status"] == "fail"]
            reviews = [item for item in concerns if item["status"] == "needs_review"]
            assessment["principle_concerns"] = failures + reviews[
                : max(0, 4 - len(failures))
            ]
        if details:
            assessment["principles"] = principles
    detail_sections = {
        "security_risks": bool(risks),
        "tool_inventory": record["tools_count"] > 0,
        "tool_risks": risky_tool_summary["total"] > 0,
        "capability_map": assessment["kind"] == "risk_rating"
        or bool(record["capabilities"]),
        "evidence": risk_evidence_count > 0 or principle_evidence_count > 0,
        "remediation": remediation_step_count > 0 or tool_recommendation_count > 0,
        "review_principles": principle_count > 0,
        "source_details": any(
            record["urls"][key]
            for key in ("listing", "source", "repository", "homepage")
        ),
    }
    return {
        **candidate_view(record),
        "description": clean_display(
            record["long_description"] or record["description"],
            12000 if details else 1200,
        ),
        "assessment": assessment,
        "security_risks": risks if details else risks[:2],
        "tags": record["tags"] if details else record["tags"][:12],
        "risky_tools": risky_tools if details else [],
        "capabilities": record["capabilities"] if details else [],
        "tools_count": record["tools_count"],
        "compact_summary": {
            "security_risk_count": len(risks),
            "security_risk_evidence_count": risk_evidence_count,
            "remediation_step_count": remediation_step_count,
            "capability_flag_count": len(flags),
            "capability_highlights": capability_highlights(flags),
            "capability_flags": flags if details else [],
            "tools_count": record["tools_count"],
            "risky_tool_counts": risky_tool_summary,
            "risky_tool_highlights": risky_tool_highlights,
            "critical_high_tool_count": len(critical_high_tools),
            "critical_high_tool_highlights": critical_high_tool_highlights,
            "critical_high_tool_omitted_count": max(
                0, len(critical_high_tools) - len(critical_high_tool_highlights)
            ),
            "detail_sections": detail_sections,
        },
        "source_code_reviewed": record["source_code_reviewed"],
        "analysis_method": record["analysis_method"] or None,
        "assessment_updated_at": record["last_scanned"] or record["added_at"] or None,
        "plutonium_url": record["urls"]["plutonium"],
    }


def build_result(
    query: str,
    records: list[dict[str, Any]],
    provenance: dict[str, Any],
    *,
    details: bool,
) -> dict[str, Any]:
    status, matches, reason = find_matches(query, records)
    result: dict[str, Any] = {
        "schema_version": 1,
        "status": status,
        "query": query,
        "match_reason": reason,
        "catalog_provenance": provenance,
    }
    if status == "match":
        result["item"] = match_view(matches[0], details)
    elif status == "ambiguous":
        result["matches"] = [candidate_view(record) for record in matches]
    else:
        result["suggestions"] = (
            [] if reason == "unknown_identifier" else suggestions(normalize_text(query), records)
        )
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "query",
        nargs="?",
        help="Exact product name, optionally with ecosystem or publisher",
    )
    parser.add_argument(
        "--query-base64",
        metavar="TOKEN",
        help="Canonical RFC 4648 base64-encoded UTF-8 query for shell-only callers",
    )
    parser.add_argument("--details", action="store_true", help="Return additional evidence")
    args = parser.parse_args(argv)
    if (args.query is None) == (args.query_base64 is None):
        parser.error("provide exactly one query argument or --query-base64 token")
    if args.query_base64 is not None:
        token = args.query_base64
        if (
            not 1 <= len(token) <= MAX_QUERY_BASE64_CHARS
            or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", token)
        ):
            parser.error("--query-base64 must be one canonical base64 token")
        try:
            decoded = base64.b64decode(token, validate=True)
            if base64.b64encode(decoded).decode("ascii") != token:
                raise ValueError("non-canonical base64")
            args.query = decoded.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            parser.error("--query-base64 must encode a valid UTF-8 query")
    if (
        not args.query.strip()
        or len(args.query) > MAX_QUERY_CHARS
        or any(
            unicodedata.category(character).startswith("C")
            for character in args.query
        )
    ):
        parser.error(f"query must contain 1-{MAX_QUERY_CHARS} characters")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        records, provenance = retrieve_catalog(datetime.now(timezone.utc))
        result = build_result(args.query, records, provenance, details=args.details)
        exit_code = 0
    except LookupError as exc:
        result = {
            "schema_version": 1,
            "status": "unavailable",
            "query": args.query,
            "reason_code": exc.reason_code,
        }
        exit_code = 2
    except Exception:
        result = {
            "schema_version": 1,
            "status": "unavailable",
            "query": args.query,
            "reason_code": "catalog_invalid",
        }
        exit_code = 2
    json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True, indent=2)
    sys.stdout.write("\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
