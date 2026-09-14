"""Private S3 catalog loading and bounded Plutonium lookup results."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import time
import unicodedata
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse, urlunparse


MAX_CATALOG_BYTES = 32 * 1024 * 1024
MAX_POINTER_BYTES = 64 * 1024
MAX_RECORDS = 20_000
MAX_CATALOG_AGE = timedelta(days=45)
CLOCK_SKEW = timedelta(minutes=10)
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
ALLOWED_RISKS = {"none", "low", "medium", "high", "critical"}
ALLOWED_PRINCIPLE_STATUSES = {"pass", "not_applicable", "needs_review", "fail"}
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


class CatalogError(RuntimeError):
    """An internal catalog failure safe to reduce to a public reason code."""


def _plain_int(value: Any) -> bool:
    return type(value) is int


def _text(value: Any, maximum: int, *, required: bool = False) -> str:
    if not isinstance(value, str):
        if required:
            raise CatalogError("catalog_invalid")
        return ""
    cleaned = " ".join(value.split())
    cleaned = "".join(
        character
        for character in cleaned
        if not unicodedata.category(character).startswith("C")
    )
    if required and not cleaned:
        raise CatalogError("catalog_invalid")
    if len(cleaned) > maximum:
        cleaned = cleaned[:maximum].rstrip()
    return cleaned


def _string_list(value: Any, *, limit: int, item_limit: int) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise CatalogError("catalog_invalid")
    result = [_text(item, item_limit, required=True) for item in value]
    if len(result) != len(set(result)):
        raise CatalogError("catalog_invalid")
    return result


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


def _validate_plutonium_url(value: Any, planet: str, routes: list[str]) -> str:
    url = normalize_url(value)
    if not url:
        raise CatalogError("catalog_invalid")
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "plutonium.pluto.security"
        or parsed.port is not None
        or parsed.path != "/detail.html"
    ):
        raise CatalogError("catalog_invalid")
    try:
        params = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise CatalogError("catalog_invalid") from exc
    if set(params) - {"planet", "did", "utm_source", "utm_medium", "utm_campaign"}:
        raise CatalogError("catalog_invalid")
    if (
        params.get("planet") != [planet]
        or len(params.get("did", [])) != 1
        or params["did"][0] not in routes
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise CatalogError("catalog_invalid")
    return url


def _validate_security_risks(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 200:
        raise CatalogError("catalog_invalid")
    risks = []
    for raw in value:
        if not isinstance(raw, dict):
            raise CatalogError("catalog_invalid")
        severity = raw.get("severity")
        if severity not in ALLOWED_RISKS:
            raise CatalogError("catalog_invalid")
        steps = _string_list(raw.get("remediation_steps", []), limit=100, item_limit=4000)
        risks.append(
            {
                "risk_type": _text(raw.get("risk_type"), 128),
                "severity": severity,
                "title": _text(raw.get("title"), 1000),
                "description": _text(raw.get("description"), 12_000),
                "evidence": _text(raw.get("evidence"), 20_000),
                "remediation_steps": steps,
            }
        )
    return risks


def _validate_risky_tools(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 1000:
        raise CatalogError("catalog_invalid")
    tools = []
    for raw in value:
        if not isinstance(raw, dict) or not isinstance(raw.get("risk"), dict):
            raise CatalogError("catalog_invalid")
        risk = raw["risk"]
        if risk.get("level") not in ALLOWED_RISKS:
            raise CatalogError("catalog_invalid")
        tools.append(
            {
                "name": _text(raw.get("name"), 1000, required=True),
                "description": _text(raw.get("description"), 8000),
                "risk": {
                    "level": risk["level"],
                    "category": _text(risk.get("category"), 256),
                    "why": _text(risk.get("why"), 12_000),
                    "recommendation": _text(risk.get("recommendation"), 12_000),
                },
            }
        )
    return tools


def _validate_capabilities(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > 1000:
        raise CatalogError("catalog_invalid")
    capabilities = []
    for raw in value:
        if not isinstance(raw, dict):
            raise CatalogError("catalog_invalid")
        capabilities.append(
            {
                "name": _text(raw.get("name"), 1000, required=True),
                "description": _text(raw.get("description"), 8000),
            }
        )
    return capabilities


def _validate_assessment(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogError("catalog_invalid")
    kind = value.get("kind")
    if kind == "risk_rating":
        if value.get("level") not in ALLOWED_RISKS:
            raise CatalogError("catalog_invalid")
        return {"kind": kind, "level": value["level"]}
    if kind != "trusted_membership":
        raise CatalogError("catalog_invalid")
    principles = []
    raw_principles = value.get("principles", [])
    if not isinstance(raw_principles, list) or len(raw_principles) > 100:
        raise CatalogError("catalog_invalid")
    for raw in raw_principles:
        if not isinstance(raw, dict) or raw.get("status") not in ALLOWED_PRINCIPLE_STATUSES:
            raise CatalogError("catalog_invalid")
        principles.append(
            {
                "key": _text(raw.get("key"), 256, required=True),
                "label": _text(raw.get("label"), 1000, required=True),
                "description": _text(raw.get("description"), 8000),
                "status": raw["status"],
                "evidence": _text(raw.get("evidence"), 20_000),
            }
        )
    source_risk = value.get("source_risk_level")
    if source_risk is not None and source_risk not in ALLOWED_RISKS:
        raise CatalogError("catalog_invalid")
    result: dict[str, Any] = {"kind": kind, "principles": principles}
    if source_risk is not None:
        result["source_risk_level"] = source_risk
    return result


def _validate_record(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise CatalogError("catalog_invalid")
    planet = raw.get("planet")
    item_type = raw.get("type")
    if planet not in ALLOWED_PLANETS or item_type not in ALLOWED_TYPES:
        raise CatalogError("catalog_invalid")
    routes = _string_list(raw.get("route_dids"), limit=20, item_limit=255)
    if not routes:
        raise CatalogError("catalog_invalid")
    urls = raw.get("urls")
    if not isinstance(urls, dict):
        raise CatalogError("catalog_invalid")
    clean_urls = {
        key: normalize_url(urls.get(key))
        for key in ("listing", "source", "repository", "homepage")
    }
    clean_urls["plutonium"] = _validate_plutonium_url(
        urls.get("plutonium"), planet, routes
    )
    tools_count = raw.get("tools_count")
    if not _plain_int(tools_count) or not 0 <= tools_count <= 100_000:
        raise CatalogError("catalog_invalid")
    source_reviewed = raw.get("source_code_reviewed")
    if source_reviewed is None:
        source_reviewed = False
    if type(source_reviewed) is not bool:
        raise CatalogError("catalog_invalid")
    record = {
        "record_id": _text(raw.get("record_id"), 1000, required=True),
        "planet": planet,
        "ecosystem": _text(raw.get("ecosystem"), 1000),
        "type": item_type,
        "category": _text(raw.get("category"), 1000),
        "name": _text(raw.get("name"), 1000, required=True),
        "publisher": _text(raw.get("publisher"), 1000),
        "id": _text(raw.get("id"), 1000),
        "uuid": _text(raw.get("uuid"), 1000),
        "route_dids": routes,
        "description": _text(raw.get("description"), 12_000),
        "long_description": _text(raw.get("long_description"), 40_000),
        "assessment": _validate_assessment(raw.get("assessment")),
        "security_risks": _validate_security_risks(raw.get("security_risks")),
        "tags": _string_list(raw.get("tags"), limit=200, item_limit=128),
        "risky_tools": _validate_risky_tools(raw.get("risky_tools")),
        "capabilities": _validate_capabilities(raw.get("capabilities")),
        "tools_count": tools_count,
        "source_code_reviewed": source_reviewed,
        "analysis_method": _text(raw.get("analysis_method"), 1000),
        "added_at": _text(raw.get("added_at"), 128),
        "last_scanned": _text(raw.get("last_scanned"), 128),
        "urls": clean_urls,
    }
    return record


def validate_catalog(payload: bytes, pointer: dict[str, Any]) -> list[dict[str, Any]]:
    if not payload or len(payload) > MAX_CATALOG_BYTES:
        raise CatalogError("catalog_invalid")
    if len(payload) != pointer["bytes"] or hashlib.sha256(payload).hexdigest() != pointer["sha256"]:
        raise CatalogError("catalog_verification_failed")
    try:
        raw = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogError("catalog_invalid") from exc
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "records"}:
        raise CatalogError("catalog_invalid")
    if raw.get("schema_version") != 1 or not isinstance(raw.get("records"), list):
        raise CatalogError("catalog_invalid")
    if len(raw["records"]) != pointer["record_count"] or len(raw["records"]) > MAX_RECORDS:
        raise CatalogError("catalog_invalid")
    records = [_validate_record(record) for record in raw["records"]]
    record_ids = [record["record_id"] for record in records]
    if len(record_ids) != len(set(record_ids)):
        raise CatalogError("catalog_invalid")
    actual_counts = dict(sorted(Counter(record["planet"] for record in records).items()))
    if actual_counts != pointer["catalog_counts"]:
        raise CatalogError("catalog_invalid")
    return records


def validate_pointer(
    payload: bytes, *, now: datetime | None = None
) -> dict[str, Any]:
    if not payload or len(payload) > MAX_POINTER_BYTES:
        raise CatalogError("catalog_pointer_invalid")
    try:
        raw = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogError("catalog_pointer_invalid") from exc
    required = {
        "schema_version",
        "catalog_key",
        "sha256",
        "bytes",
        "record_count",
        "catalog_counts",
        "published_at",
        "expires_at",
        "source_commit",
    }
    if not isinstance(raw, dict) or set(raw) != required or raw.get("schema_version") != 1:
        raise CatalogError("catalog_pointer_invalid")
    if not re.fullmatch(r"releases/[0-9a-f]{64}/catalog\.json", str(raw.get("catalog_key", ""))):
        raise CatalogError("catalog_pointer_invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", str(raw.get("sha256", ""))):
        raise CatalogError("catalog_pointer_invalid")
    if not _plain_int(raw.get("bytes")) or not 1 <= raw["bytes"] <= MAX_CATALOG_BYTES:
        raise CatalogError("catalog_pointer_invalid")
    if not _plain_int(raw.get("record_count")) or not 1 <= raw["record_count"] <= MAX_RECORDS:
        raise CatalogError("catalog_pointer_invalid")
    counts = raw.get("catalog_counts")
    if (
        not isinstance(counts, dict)
        or set(counts) - ALLOWED_PLANETS
        or any(not _plain_int(value) or value < 0 for value in counts.values())
        or sum(counts.values()) != raw["record_count"]
    ):
        raise CatalogError("catalog_pointer_invalid")
    published_at = _text(raw.get("published_at"), 128, required=True)
    expires_at = _text(raw.get("expires_at"), 128, required=True)
    timestamp_pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
    if not re.fullmatch(timestamp_pattern, published_at) or not re.fullmatch(
        timestamp_pattern, expires_at
    ):
        raise CatalogError("catalog_pointer_invalid")
    try:
        published = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
        expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CatalogError("catalog_pointer_invalid") from exc
    current = now or datetime.now(timezone.utc)
    if (
        published > current + CLOCK_SKEW
        or expires < current - CLOCK_SKEW
        or expires <= published
        or expires - published > MAX_CATALOG_AGE
        or current - published > MAX_CATALOG_AGE
    ):
        raise CatalogError("catalog_stale")
    source_commit = _text(raw.get("source_commit"), 128)
    if source_commit and not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise CatalogError("catalog_pointer_invalid")
    return {
        **raw,
        "published_at": published_at,
        "expires_at": expires_at,
        "source_commit": source_commit,
        "catalog_counts": dict(sorted(counts.items())),
    }


def _read_s3_body(client: Any, bucket: str, key: str, maximum: int) -> bytes:
    try:
        response = client.get_object(Bucket=bucket, Key=key)
        body = response["Body"]
        try:
            payload = body.read(maximum + 1)
        finally:
            close = getattr(body, "close", None)
            if close:
                close()
    except Exception as exc:
        raise CatalogError("catalog_unavailable") from exc
    if not isinstance(payload, bytes) or len(payload) > maximum:
        raise CatalogError("catalog_invalid")
    return payload


class CatalogStore:
    """Load an immutable catalog selected by a small, atomically replaced pointer."""

    def __init__(
        self,
        *,
        client: Any | None = None,
        bucket: str | None = None,
        pointer_key: str | None = None,
        ttl_seconds: int | None = None,
        clock: Callable[[], float] = time.monotonic,
        utcnow: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if client is None:
            import boto3

            client = boto3.client("s3")
        self.client = client
        self.bucket = bucket or os.environ["CATALOG_BUCKET"]
        self.pointer_key = pointer_key or os.environ.get("CATALOG_POINTER_KEY", "current.json")
        self.ttl_seconds = ttl_seconds or int(os.environ.get("CATALOG_CACHE_TTL_SECONDS", "60"))
        self.clock = clock
        self.utcnow = utcnow
        self._cached_at = 0.0
        self._pointer: dict[str, Any] | None = None
        self._records: list[dict[str, Any]] | None = None

    def load(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        now = self.clock()
        if self._records is not None and now - self._cached_at < self.ttl_seconds:
            return self._records, self._provenance(self._pointer)
        pointer = validate_pointer(
            _read_s3_body(self.client, self.bucket, self.pointer_key, MAX_POINTER_BYTES),
            now=self.utcnow(),
        )
        if self._records is None or self._pointer is None or pointer["sha256"] != self._pointer["sha256"]:
            catalog = _read_s3_body(
                self.client, self.bucket, pointer["catalog_key"], pointer["bytes"]
            )
            self._records = validate_catalog(catalog, pointer)
        self._pointer = pointer
        self._cached_at = now
        return self._records, self._provenance(pointer)

    @staticmethod
    def _provenance(pointer: dict[str, Any] | None) -> dict[str, Any]:
        if pointer is None:
            raise CatalogError("catalog_unavailable")
        return {
            "verification": "private-s3+sha256",
            "published_at": pointer["published_at"],
            "record_count": pointer["record_count"],
            "catalog_counts": pointer["catalog_counts"],
        }


def _record_identifiers(record: dict[str, Any]) -> set[str]:
    identifiers = {
        record[key].strip().casefold()
        for key in ("record_id", "id", "uuid")
        if record.get(key)
    }
    for route in record["route_dids"]:
        identifiers.add(route.casefold())
        identifiers.add(f"{record['planet']}:{route}".casefold())
    for value in record["urls"].values():
        if value:
            identifiers.add(value.casefold())
    return identifiers


def _identifier_from_query(query: str) -> str:
    normalized = normalize_url(query)
    if normalized:
        parsed = urlparse(normalized)
        if parsed.hostname == "plutonium.pluto.security" and parsed.path == "/detail.html":
            try:
                params = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
            except ValueError:
                return normalized.casefold()
            if len(params.get("planet", [])) == 1 and len(params.get("did", [])) == 1:
                return f"{params['planet'][0]}:{params['did'][0]}".casefold()
        return normalized.casefold()
    return query.strip().casefold()


def _has_phrase(text: str, phrase: str) -> bool:
    return bool(phrase and re.search(rf"(?:^| ){re.escape(phrase)}(?: |$)", text))


def _remove_phrase(text: str, phrase: str, *, count: int = 0) -> tuple[str, bool]:
    updated, replacements = re.subn(
        rf"(?:^| ){re.escape(phrase)}(?= |$)", " ", text, count=count
    )
    return " ".join(updated.split()), bool(replacements)


def _consume_qualifiers(text: str, qualifiers: dict[str, set[str]]) -> tuple[str, set[str] | None]:
    allowed: set[str] | None = None
    for phrase in sorted(qualifiers, key=lambda item: (-len(item.split()), -len(item), item)):
        text, matched = _remove_phrase(text, phrase)
        if matched:
            allowed = set(qualifiers[phrase]) if allowed is None else allowed & qualifiers[phrase]
    return text, allowed


def _candidate_accepts_qualifiers(query: str, record: dict[str, Any]) -> bool:
    name = normalize_text(record["name"])
    publisher = normalize_text(record["publisher"])
    residual, matched_name = _remove_phrase(query, name, count=1)
    if matched_name:
        if publisher and publisher != name:
            residual, _ = _remove_phrase(residual, publisher, count=1)
        residual, planets = _consume_qualifiers(residual, PLANET_QUALIFIERS)
        residual, types = _consume_qualifiers(residual, TYPE_QUALIFIERS)
        if (
            not residual
            and (planets is None or record["planet"] in planets)
            and (types is None or record["type"] in types)
        ):
            return True
    return False


def find_matches(query: str, records: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]], str]:
    identifier = _identifier_from_query(query)
    explicit = bool(
        normalize_url(query)
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            query.strip(),
            re.IGNORECASE,
        )
        or query.strip().casefold().startswith(tuple(f"{planet}:" for planet in ALLOWED_PLANETS))
    )
    if explicit:
        matches = [record for record in records if identifier in _record_identifiers(record)]
        if matches:
            return ("match" if len(matches) == 1 else "ambiguous"), matches, "stable_identifier"
        return "no_match", [], "unknown_identifier"
    normalized = normalize_text(query)
    exact = [record for record in records if normalize_text(record["name"]) == normalized]
    if exact:
        return ("match" if len(exact) == 1 else "ambiguous"), exact, "exact_name"
    candidates = [record for record in records if _has_phrase(normalized, normalize_text(record["name"]))]
    if candidates:
        longest = max(len(normalize_text(record["name"])) for record in candidates)
        qualified = [
            record
            for record in candidates
            if len(normalize_text(record["name"])) == longest
            and _candidate_accepts_qualifiers(normalized, record)
        ]
        if qualified:
            return ("match" if len(qualified) == 1 else "ambiguous"), qualified, "qualified_name"
    matches = [record for record in records if identifier in _record_identifiers(record)]
    if matches:
        return ("match" if len(matches) == 1 else "ambiguous"), matches, "stable_identifier"
    return "no_match", [], "no_reliable_match"


def _candidate_view(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": record["record_id"],
        "name": record["name"],
        "publisher": record["publisher"] or None,
        "type": record["type"],
        "type_label": TYPE_LABELS[record["type"]],
        "planet": record["planet"],
        "ecosystem": record["ecosystem"] or None,
    }


def _suggestions(query: str, records: list[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
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
    return [_candidate_view(record) for _, _, _, record in scored[:limit]]


def _match_view(record: dict[str, Any], details: bool) -> dict[str, Any]:
    risks = sorted(
        record["security_risks"],
        key=lambda risk: (RISK_ORDER[risk["severity"]], normalize_text(risk["title"])),
    )
    risky_tools = sorted(
        record["risky_tools"],
        key=lambda tool: (RISK_ORDER[tool["risk"]["level"]], normalize_text(tool["name"])),
    )
    tags = set(record["tags"])
    flags = [
        {"key": key, "label": label}
        for key, label in TAG_CAPABILITY_DEFINITIONS
        if key in tags
    ]
    flags_by_key = {flag["key"]: flag for flag in flags}
    highlights = [
        flags_by_key[key] for key in CAPABILITY_HIGHLIGHT_PRIORITY if key in flags_by_key
    ][:3]
    counts = Counter(
        tool["risk"]["level"]
        for tool in risky_tools
        if tool["risk"]["level"] != "none"
    )
    risky_summary = {
        "total": sum(counts.values()),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
    }
    critical_high = [tool for tool in risky_tools if tool["risk"]["level"] in {"critical", "high"}]
    assessment = dict(record["assessment"])
    principles = assessment.pop("principles", [])
    principle_counts = Counter(principle["status"] for principle in principles)
    concerns = sorted(
        [p for p in principles if p["status"] in {"fail", "needs_review"}],
        key=lambda p: (0 if p["status"] == "fail" else 1, normalize_text(p["label"])),
    )
    if assessment["kind"] == "trusted_membership":
        failures = [item for item in concerns if item["status"] == "fail"]
        reviews = [item for item in concerns if item["status"] == "needs_review"]
        assessment.update(
            {
                "principle_summary": dict(sorted(principle_counts.items())),
                "principle_count": len(principles),
                "principle_concern_count": len(concerns),
                "principle_evidence_count": sum(bool(item["evidence"]) for item in principles),
                "principle_concerns": concerns if details else failures + reviews[: max(0, 4 - len(failures))],
            }
        )
        if details:
            assessment["principles"] = principles
    risk_evidence_count = sum(bool(risk["evidence"]) for risk in risks)
    remediation_count = sum(len(risk["remediation_steps"]) for risk in risks)
    tool_recommendations = sum(bool(tool["risk"]["recommendation"]) for tool in risky_tools)
    return {
        **_candidate_view(record),
        "description": _text(
            record["long_description"] or record["description"], 12_000 if details else 1200
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
            "remediation_step_count": remediation_count,
            "capability_flag_count": len(flags),
            "capability_highlights": highlights,
            "capability_flags": flags if details else [],
            "tools_count": record["tools_count"],
            "risky_tool_counts": risky_summary,
            "risky_tool_highlights": [
                {
                    "name": tool["name"],
                    "level": tool["risk"]["level"],
                    "category": tool["risk"]["category"],
                }
                for tool in risky_tools
                if tool["risk"]["level"] != "none"
            ][:3],
            "critical_high_tool_count": len(critical_high),
            "critical_high_tool_highlights": [
                {
                    "name": tool["name"],
                    "level": tool["risk"]["level"],
                    "category": tool["risk"]["category"],
                }
                for tool in critical_high[:3]
            ],
            "critical_high_tool_omitted_count": max(0, len(critical_high) - 3),
            "detail_sections": {
                "security_risks": bool(risks),
                "tool_inventory": record["tools_count"] > 0,
                "tool_risks": risky_summary["total"] > 0,
                "capability_map": assessment["kind"] == "risk_rating" or bool(record["capabilities"]),
                "evidence": risk_evidence_count > 0
                or any(bool(item["evidence"]) for item in principles),
                "remediation": remediation_count > 0 or tool_recommendations > 0,
                "review_principles": bool(principles),
                "source_details": any(
                    record["urls"][key]
                    for key in ("listing", "source", "repository", "homepage")
                ),
            },
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
        result["item"] = _match_view(matches[0], details)
    elif status == "ambiguous":
        result["matches"] = [_candidate_view(record) for record in matches[:20]]
    else:
        result["suggestions"] = (
            [] if reason == "unknown_identifier" else _suggestions(normalize_text(query), records)
        )
    return result
