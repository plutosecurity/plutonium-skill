"""AWS Lambda entry point for the public, rate-limited lookup API."""

from __future__ import annotations

import base64
import binascii
import json
import logging
import time
import unicodedata
from typing import Any

from catalog import CatalogError, CatalogStore, build_result


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)
MAX_BODY_BYTES = 4096
MAX_QUERY_CHARS = 500
STORE: CatalogStore | None = None


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
        },
        "body": json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        "isBase64Encoded": False,
    }


def _error(status_code: int, code: str) -> dict[str, Any]:
    return _response(status_code, {"schema_version": 1, "status": "error", "error": code})


def _method_and_path(event: dict[str, Any]) -> tuple[str, str]:
    request_context = event.get("requestContext")
    if not isinstance(request_context, dict):
        return "", ""
    http = request_context.get("http")
    if not isinstance(http, dict):
        return "", ""
    return str(http.get("method", "")).upper(), str(event.get("rawPath", ""))


def _decode_body(event: dict[str, Any]) -> bytes:
    body = event.get("body")
    if not isinstance(body, str):
        raise ValueError("invalid_request")
    try:
        payload = base64.b64decode(body, validate=True) if event.get("isBase64Encoded") else body.encode("utf-8")
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("invalid_request") from exc
    if not payload or len(payload) > MAX_BODY_BYTES:
        raise ValueError("invalid_request")
    return payload


def _parse_request(event: dict[str, Any]) -> tuple[str, bool]:
    raw_headers = event.get("headers")
    if not isinstance(raw_headers, dict):
        raise ValueError("invalid_request")
    headers = {str(key).lower(): str(value) for key, value in raw_headers.items()}
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise TypeError("unsupported_media_type")
    try:
        raw = json.loads(_decode_body(event))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid_request") from exc
    if not isinstance(raw, dict) or set(raw) - {"query", "details"} or "query" not in raw:
        raise ValueError("invalid_request")
    query = raw["query"]
    details = raw.get("details", False)
    if (
        not isinstance(query, str)
        or not query.strip()
        or len(query) > MAX_QUERY_CHARS
        or type(details) is not bool
        or any(unicodedata.category(character).startswith("C") for character in query)
    ):
        raise ValueError("invalid_request")
    return query, details


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    global STORE
    started = time.monotonic()
    method, path = _method_and_path(event)
    if method == "GET" and path == "/v1/health":
        return _response(200, {"schema_version": 1, "status": "ok"})
    if method != "POST" or path != "/v1/lookup":
        return _error(404, "not_found")
    try:
        query, details = _parse_request(event)
    except TypeError:
        return _error(415, "unsupported_media_type")
    except ValueError:
        return _error(400, "invalid_request")
    try:
        if STORE is None:
            STORE = CatalogStore()
        records, provenance = STORE.load()
        result = build_result(query, records, provenance, details=details)
    except CatalogError as exc:
        LOGGER.error("lookup unavailable reason=%s", str(exc))
        return _error(503, "catalog_unavailable")
    except Exception:
        LOGGER.exception("unexpected lookup failure")
        return _error(503, "catalog_unavailable")
    LOGGER.info(
        "lookup completed status=%s details=%s duration_ms=%d",
        result["status"],
        details,
        int((time.monotonic() - started) * 1000),
    )
    return _response(200, result)
