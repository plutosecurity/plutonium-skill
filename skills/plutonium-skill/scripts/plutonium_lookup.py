#!/usr/bin/env python3
"""Query the bounded Plutonium lookup API and validate its response."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import ssl
import sys
import unicodedata
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


VERSION = "0.2.0"
SKILL_ROOT = Path(__file__).resolve().parent.parent
API_CONFIG_PATH = SKILL_ROOT / "references" / "api.json"
MAX_QUERY_CHARS = 500
MAX_QUERY_BASE64_CHARS = 4 * ((MAX_QUERY_CHARS * 4 + 2) // 3)
MAX_RESPONSE_BYTES = 512 * 1024
REQUEST_TIMEOUT_SECONDS = 15
ALLOWED_STATUSES = {"match", "ambiguous", "no_match"}
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
TYPE_LABELS = {
    "connector": "Connector",
    "web_connector": "Web Connector",
    "interactive_connector": "Interactive Connector",
    "desktop_extension": "Desktop Extension",
    "mcp": "MCP Server",
    "plugin": "Plugin",
    "skill": "Skill",
}


class LookupError(RuntimeError):
    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _string(value: Any, *, maximum: int, required: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum:
        raise LookupError("response_invalid")
    if required and not value.strip():
        raise LookupError("response_invalid")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise LookupError("response_invalid")
    return value


def _integer(value: Any, *, minimum: int = 0, maximum: int = 1_000_000) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise LookupError("response_invalid")
    return value


def _exact_keys(
    value: Any, required: set[str], optional: set[str] | None = None
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LookupError("response_invalid")
    optional = optional or set()
    if not required <= set(value) or set(value) - required - optional:
        raise LookupError("response_invalid")
    return value


def _list(value: Any, *, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise LookupError("response_invalid")
    return value


def _validate_endpoint(endpoint: Any, *, allow_placeholder: bool) -> str:
    endpoint = _string(endpoint, maximum=2048, required=True)
    try:
        parsed = urlparse(endpoint)
        port = parsed.port
    except ValueError as exc:
        raise LookupError("configuration_invalid") from exc
    host = (parsed.hostname or "").casefold()
    allowed_host = host.endswith(
        ".execute-api.eu-central-1.amazonaws.com"
    ) or host.endswith(".pluto.security")
    if allow_placeholder and host == "replace-after-deploy.invalid":
        allowed_host = True
    if (
        parsed.scheme != "https"
        or not allowed_host
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/v1/lookup"
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise LookupError("configuration_invalid")
    return endpoint


def load_endpoint() -> str:
    try:
        raw = json.loads(API_CONFIG_PATH.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LookupError("configuration_invalid") from exc
    raw = _exact_keys(raw, {"schema_version", "endpoint"})
    if raw["schema_version"] != 1:
        raise LookupError("configuration_invalid")
    endpoint = _validate_endpoint(raw["endpoint"], allow_placeholder=True)
    if urlparse(endpoint).hostname == "replace-after-deploy.invalid":
        raise LookupError("endpoint_unconfigured")
    return endpoint


def _validate_candidate(raw: Any) -> dict[str, Any]:
    raw = _exact_keys(
        raw,
        {
            "record_id",
            "name",
            "publisher",
            "type",
            "type_label",
            "planet",
            "ecosystem",
        },
    )
    if (
        raw["type"] not in ALLOWED_TYPES
        or raw["planet"] not in ALLOWED_PLANETS
        or raw["type_label"] != TYPE_LABELS.get(raw["type"])
    ):
        raise LookupError("response_invalid")
    for key in ("record_id", "name", "type_label"):
        _string(raw[key], maximum=1000, required=True)
    for key in ("publisher", "ecosystem"):
        if raw[key] is not None:
            _string(raw[key], maximum=1000)
    return raw


def _validate_risk(raw: Any) -> None:
    raw = _exact_keys(
        raw,
        {
            "risk_type",
            "severity",
            "title",
            "description",
            "evidence",
            "remediation_steps",
        },
    )
    if raw["severity"] not in ALLOWED_RISKS:
        raise LookupError("response_invalid")
    for key, maximum in (
        ("risk_type", 128),
        ("title", 1000),
        ("description", 12_000),
        ("evidence", 20_000),
    ):
        _string(raw[key], maximum=maximum)
    for step in _list(raw["remediation_steps"], maximum=100):
        _string(step, maximum=4000, required=True)


def _validate_tool(raw: Any) -> None:
    raw = _exact_keys(raw, {"name", "description", "risk"})
    _string(raw["name"], maximum=1000, required=True)
    _string(raw["description"], maximum=8000)
    risk = _exact_keys(raw["risk"], {"level", "category", "why", "recommendation"})
    if risk["level"] not in ALLOWED_RISKS:
        raise LookupError("response_invalid")
    for key, maximum in (
        ("category", 256),
        ("why", 12_000),
        ("recommendation", 12_000),
    ):
        _string(risk[key], maximum=maximum)


def _validate_capability(raw: Any) -> None:
    raw = _exact_keys(raw, {"name", "description"})
    _string(raw["name"], maximum=1000, required=True)
    _string(raw["description"], maximum=8000)


def _validate_principle(raw: Any) -> None:
    raw = _exact_keys(raw, {"key", "label", "description", "status", "evidence"})
    if raw["status"] not in ALLOWED_PRINCIPLE_STATUSES:
        raise LookupError("response_invalid")
    _string(raw["key"], maximum=256, required=True)
    _string(raw["label"], maximum=1000, required=True)
    _string(raw["description"], maximum=8000)
    _string(raw["evidence"], maximum=20_000)


def _validate_assessment(raw: Any) -> None:
    raw = _exact_keys(
        raw,
        {"kind"},
        {
            "level",
            "source_risk_level",
            "principle_summary",
            "principle_count",
            "principle_concern_count",
            "principle_evidence_count",
            "principle_concerns",
            "principles",
        },
    )
    if raw["kind"] == "risk_rating":
        if set(raw) != {"kind", "level"} or raw["level"] not in ALLOWED_RISKS:
            raise LookupError("response_invalid")
        return
    if raw["kind"] != "trusted_membership" or "principle_concerns" not in raw:
        raise LookupError("response_invalid")
    if (
        raw.get("source_risk_level") is not None
        and raw["source_risk_level"] not in ALLOWED_RISKS
    ):
        raise LookupError("response_invalid")
    for key in (
        "principle_count",
        "principle_concern_count",
        "principle_evidence_count",
    ):
        _integer(raw.get(key))
    summary = raw.get("principle_summary")
    if not isinstance(summary, dict) or set(summary) - ALLOWED_PRINCIPLE_STATUSES:
        raise LookupError("response_invalid")
    for count in summary.values():
        _integer(count)
    for principle in _list(raw["principle_concerns"], maximum=100):
        _validate_principle(principle)
    if "principles" in raw:
        for principle in _list(raw["principles"], maximum=100):
            _validate_principle(principle)


def _validate_flag(raw: Any) -> None:
    raw = _exact_keys(raw, {"key", "label"})
    _string(raw["key"], maximum=128, required=True)
    _string(raw["label"], maximum=1000, required=True)


def _validate_tool_highlight(raw: Any) -> None:
    raw = _exact_keys(raw, {"name", "level", "category"})
    _string(raw["name"], maximum=1000, required=True)
    _string(raw["category"], maximum=256)
    if raw["level"] not in ALLOWED_RISKS:
        raise LookupError("response_invalid")


def _validate_compact_summary(raw: Any) -> None:
    keys = {
        "security_risk_count",
        "security_risk_evidence_count",
        "remediation_step_count",
        "capability_flag_count",
        "capability_highlights",
        "capability_flags",
        "tools_count",
        "risky_tool_counts",
        "risky_tool_highlights",
        "critical_high_tool_count",
        "critical_high_tool_highlights",
        "critical_high_tool_omitted_count",
        "detail_sections",
    }
    raw = _exact_keys(raw, keys)
    count_keys = {
        "security_risk_count",
        "security_risk_evidence_count",
        "remediation_step_count",
        "capability_flag_count",
        "tools_count",
        "critical_high_tool_count",
        "critical_high_tool_omitted_count",
    }
    for key in count_keys:
        _integer(raw[key])
    for key in ("capability_highlights", "capability_flags"):
        for flag in _list(raw[key], maximum=20):
            _validate_flag(flag)
    for key in ("risky_tool_highlights", "critical_high_tool_highlights"):
        for highlight in _list(raw[key], maximum=20):
            _validate_tool_highlight(highlight)
    counts = _exact_keys(
        raw["risky_tool_counts"], {"total", "critical", "high", "medium", "low"}
    )
    for count in counts.values():
        _integer(count)
    sections = _exact_keys(
        raw["detail_sections"],
        {
            "security_risks",
            "tool_inventory",
            "tool_risks",
            "capability_map",
            "evidence",
            "remediation",
            "review_principles",
            "source_details",
        },
    )
    if any(type(value) is not bool for value in sections.values()):
        raise LookupError("response_invalid")


def _validate_item(raw: Any) -> dict[str, Any]:
    candidate_keys = {
        "record_id",
        "name",
        "publisher",
        "type",
        "type_label",
        "planet",
        "ecosystem",
    }
    item_keys = candidate_keys | {
        "description",
        "assessment",
        "security_risks",
        "tags",
        "risky_tools",
        "capabilities",
        "tools_count",
        "compact_summary",
        "source_code_reviewed",
        "analysis_method",
        "assessment_updated_at",
        "plutonium_url",
    }
    raw = _exact_keys(raw, item_keys)
    _validate_candidate({key: raw[key] for key in candidate_keys})
    _string(raw["description"], maximum=12_000)
    _validate_assessment(raw["assessment"])
    for risk in _list(raw["security_risks"], maximum=200):
        _validate_risk(risk)
    for tag in _list(raw["tags"], maximum=200):
        _string(tag, maximum=128, required=True)
    for tool in _list(raw["risky_tools"], maximum=1000):
        _validate_tool(tool)
    for capability in _list(raw["capabilities"], maximum=1000):
        _validate_capability(capability)
    _integer(raw["tools_count"], maximum=100_000)
    _validate_compact_summary(raw["compact_summary"])
    if type(raw["source_code_reviewed"]) is not bool:
        raise LookupError("response_invalid")
    for key in ("analysis_method", "assessment_updated_at"):
        if raw[key] is not None:
            _string(raw[key], maximum=1000)
    plutonium_url = _string(raw["plutonium_url"], maximum=2048, required=True)
    parsed = urlparse(plutonium_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "plutonium.pluto.security"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/detail.html"
    ):
        raise LookupError("response_invalid")
    try:
        params = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise LookupError("response_invalid") from exc
    if params.get("planet") != [raw["planet"]] or len(params.get("did", [])) != 1:
        raise LookupError("response_invalid")
    return raw


def validate_result(raw: Any, query: str) -> dict[str, Any]:
    base = {
        "schema_version",
        "status",
        "query",
        "match_reason",
        "catalog_provenance",
    }
    raw = _exact_keys(raw, base, {"item", "matches", "suggestions"})
    if (
        raw["schema_version"] != 1
        or raw["status"] not in ALLOWED_STATUSES
        or raw["query"] != query
    ):
        raise LookupError("response_invalid")
    _string(raw["match_reason"], maximum=128, required=True)
    provenance = _exact_keys(
        raw["catalog_provenance"],
        {"verification", "published_at", "record_count", "catalog_counts"},
    )
    if provenance["verification"] != "private-s3+sha256":
        raise LookupError("response_invalid")
    published_at = _string(provenance["published_at"], maximum=128, required=True)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", published_at):
        raise LookupError("response_invalid")
    _integer(provenance["record_count"], minimum=1)
    counts = provenance["catalog_counts"]
    if not isinstance(counts, dict) or set(counts) - ALLOWED_PLANETS:
        raise LookupError("response_invalid")
    for count in counts.values():
        _integer(count)
    if sum(counts.values()) != provenance["record_count"]:
        raise LookupError("response_invalid")
    if raw["status"] == "match":
        if set(raw) != base | {"item"}:
            raise LookupError("response_invalid")
        _validate_item(raw["item"])
    elif raw["status"] == "ambiguous":
        if set(raw) != base | {"matches"}:
            raise LookupError("response_invalid")
        for candidate in _list(raw["matches"], maximum=20):
            _validate_candidate(candidate)
    else:
        if set(raw) != base | {"suggestions"}:
            raise LookupError("response_invalid")
        for candidate in _list(raw["suggestions"], maximum=5):
            _validate_candidate(candidate)
    return raw


def request_lookup(endpoint: str, query: str, *, details: bool) -> dict[str, Any]:
    body = json.dumps(
        {"query": query, "details": details},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"Plutonium-Skill/{VERSION}",
        },
    )
    opener = build_opener(NoRedirects(), HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise LookupError("service_unavailable")
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        if exc.code == 429:
            raise LookupError("rate_limited") from exc
        raise LookupError("service_unavailable") from exc
    except (OSError, TimeoutError, URLError) as exc:
        raise LookupError("service_unavailable") from exc
    if not payload or len(payload) > MAX_RESPONSE_BYTES:
        raise LookupError("response_invalid")
    try:
        raw = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LookupError("response_invalid") from exc
    return validate_result(raw, query)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query", nargs="?", help="Exact product name, optionally qualified")
    parser.add_argument("--query-base64", metavar="TOKEN")
    parser.add_argument("--details", action="store_true")
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
        result = request_lookup(load_endpoint(), args.query, details=args.details)
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
            "reason_code": "service_unavailable",
        }
        exit_code = 2
    json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True, indent=2)
    sys.stdout.write("\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
